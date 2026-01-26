import os
import sys
import json
import io
import threading
import traceback
from pathlib import Path
from contextlib import redirect_stdout

from .ps5_sdk_version_patcher import SDKVersionPatcher
from .make_fself import FakeSignedELFConverter
from .decrypt_fself import UnsignedELFConverter

class BackporkEngine:
    CONFIG_FILE = os.path.join("static", "config", "backpork.json")
    process_lock = threading.Lock()

    @staticmethod
    def load_config():
        if os.path.exists(BackporkEngine.CONFIG_FILE):
            try:
                with open(BackporkEngine.CONFIG_FILE, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {
            "input_path": "",
            "output_path": "",
            "sdk_pair": 4,
            "paid": "0x3100000000000002",
            "ptype": "fake",
            "backup": True,
            "use_fakelib": True
        }

    @staticmethod
    def save_config(config):
        os.makedirs(os.path.dirname(BackporkEngine.CONFIG_FILE), exist_ok=True)
        with open(BackporkEngine.CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)

    @staticmethod
    def run_process(data):
        if BackporkEngine.process_lock.locked():
            yield f"data: {json.dumps({'log': 'Error: Process already running', 'status': 'error'})}\n\n"
            return

        with BackporkEngine.process_lock:
            buffer = io.StringIO()
            
            try:
                BackporkEngine.save_config(data)

                mode = data.get('mode', 'downgrade')
                input_dir = Path(data.get('input_path'))
                output_dir = Path(data.get('output_path'))
                
                if not input_dir.exists():
                     yield f"data: {json.dumps({'log': f'Error: Input directory not found: {input_dir}', 'status': 'error'})}\n\n"
                     return

                sdk_pair = int(data.get('sdk_pair', 4))
                paid_str = data.get('paid', '0x3100000000000002')
                paid = int(paid_str, 16) if isinstance(paid_str, str) and paid_str.startswith('0x') else int(paid_str)
                
                ptype_str = data.get('ptype', 'fake')
                try:
                    ptype = FakeSignedELFConverter.parse_ptype(ptype_str)
                except:
                    ptype = 1
                
                backup = data.get('backup', True)
                
                fakelib = None
                if data.get('use_fakelib', True):
                    current_dir = Path(os.path.dirname(os.path.abspath(__file__)))
                    fakelib = current_dir / "fakelib"
                    if not fakelib.exists():
                        yield f"data: {json.dumps({'log': 'Warning: Fakelib directory not found in src/backpork/fakelib'})}\n\n"
                        fakelib = None

                yield f"data: {json.dumps({'log': f'--- Starting Auto-Backpork ({mode}) ---'})}\n\n"

                def worker():
                    if mode == 'downgrade':
                        print(f"Starting SDK Downgrade using Pair {sdk_pair}...")
                        patcher = SDKVersionPatcher(create_backup=backup, use_colors=False)
                        patcher.set_versions_by_pair(sdk_pair)
                        
                        elf_files = [f for f in input_dir.glob('**/*') if f.is_file() and not f.name.endswith('.bak')]
                        elf_files = [f for f in elf_files if open(f, 'rb').read(4) == b'\x7FELF']
                        
                        print(f"Found {len(elf_files)} ELF files.")
                        
                        for elf in elf_files:
                            print(f"Patching: {elf.name}")
                            patcher.patch_file(str(elf))
                            
                        print("Signing files...")
                        converter = FakeSignedELFConverter(paid=paid, ptype=ptype)
                        converter.sign_directory(str(input_dir), str(output_dir))
                        
                    elif mode == 'decrypt':
                        print("Decrypting files...")
                        converter = UnsignedELFConverter(verbose=False)
                        for root, dirs, files in os.walk(input_dir):
                            for file in files:
                                if file.endswith('.bak'): continue
                                src = os.path.join(root, file)
                                rel = os.path.relpath(src, input_dir)
                                dst = os.path.join(output_dir, rel)
                                os.makedirs(os.path.dirname(dst), exist_ok=True)
                                
                                with open(src, 'rb') as f:
                                    magic = f.read(4)
                                if magic in [b'\x4F\x15\x3D\x1D', b'\x54\x14\xF5\xEE']:
                                    print(f"Decrypting: {rel}")
                                    try:
                                        converter.convert_file(src, dst)
                                    except Exception as e:
                                        print(f"Failed to decrypt {rel}: {e}")

                    elif mode == 'full':
                        import tempfile
                        import shutil
                        
                        with tempfile.TemporaryDirectory() as temp_dir:
                            print("Phase 1: Decryption")
                            decryptor = UnsignedELFConverter(verbose=False)
                            has_files = False
                            for root, dirs, files in os.walk(input_dir):
                                for file in files:
                                    src = os.path.join(root, file)
                                    with open(src, 'rb') as f:
                                        if f.read(4) in [b'\x4F\x15\x3D\x1D', b'\x54\x14\xF5\xEE']:
                                            has_files = True
                                            rel = os.path.relpath(src, input_dir)
                                            dst = os.path.join(temp_dir, rel)
                                            os.makedirs(os.path.dirname(dst), exist_ok=True)
                                            print(f"Decrypting: {rel}")
                                            decryptor.convert_file(src, dst)
                            
                            if not has_files:
                                print("No SELF files found to decrypt.")
                                return

                            print("\nPhase 2: Downgrade")
                            patcher = SDKVersionPatcher(create_backup=backup, use_colors=False)
                            patcher.set_versions_by_pair(sdk_pair)
                            for root, dirs, files in os.walk(temp_dir):
                                for file in files:
                                    if file.endswith('.bak'): continue
                                    fpath = os.path.join(root, file)
                                    with open(fpath, 'rb') as f:
                                        if f.read(4) == b'\x7FELF':
                                            print(f"Downgrading: {file}")
                                            patcher.patch_file(fpath)

                            print("\nPhase 3: Signing")
                            converter = FakeSignedELFConverter(paid=paid, ptype=ptype)
                            converter.sign_directory(temp_dir, str(output_dir))

                class StreamToGen:
                    def write(self, s):
                        if s.strip():
                            buffer.write(s)
                    def flush(self):
                        pass

                with redirect_stdout(StreamToGen()):
                    worker()
                
                output_log = buffer.getvalue()
                yield f"data: {json.dumps({'log': output_log, 'status': 'success'})}\n\n"

            except Exception as e:
                err = traceback.format_exc()
                error_msg = f"CRITICAL ERROR:\n{err}"
                yield f"data: {json.dumps({'log': error_msg, 'status': 'error'})}\n\n"