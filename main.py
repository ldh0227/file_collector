import argparse
import os
import shutil
import hashlib
import magic
import pefile
from elftools.elf.elffile import ELFFile
from tqdm import tqdm
import pandas as pd
import sqlite3
import math


def calc_entropy(filepath):
    with open(filepath, "rb") as f:
        data = f.read()
    if not data:
        return 0.0
    occurences = [0] * 256
    for byte in data:
        occurences[byte] += 1
    entropy = 0
    for count in occurences:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy


def get_file_hashes(filepath):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def is_pe(filepath):
    try:
        pe = pefile.PE(filepath)
        return True
    except:
        return False


def is_elf(filepath):
    try:
        with open(filepath, "rb") as f:
            ELFFile(f)
        return True
    except:
        return False


def get_pe_info(filepath):
    try:
        pe = pefile.PE(filepath)
        iat_funcs = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
                for imp in entry.imports:
                    if imp.name:
                        if isinstance(imp.name, bytes):
                            func_name = imp.name.decode(errors='ignore')
                        else:
                            func_name = str(imp.name)
                        iat_funcs.append(func_name)
        # 중복 제거 및 정렬
        iat_funcs = sorted(set(iat_funcs))
        return {
            "pe_machine": hex(pe.FILE_HEADER.Machine),
            "pe_entrypoint": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "pe_sections": len(pe.sections),
            "iat_functions": ' '.join(iat_funcs)
        }
    except Exception as e:
        return {}


def get_elf_info(filepath):
    try:
        with open(filepath, "rb") as f:
            elf = ELFFile(f)
            return {
                "elf_entrypoint": hex(elf.header["e_entry"]),
                "elf_sections": elf.num_sections(),
            }
    except:
        return {}


def get_magic_type(filepath):
    try:
        with open(filepath, "rb") as f:
            buf = f.read(2048)
        return magic.from_buffer(buf)
    except Exception as e:
        return None


def collect_files(paths, only_exec):
    file_list = []
    # 제외할 경로/파일(절대경로)
    script_path = os.path.abspath(__file__)
    binaries_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "binaries"))
    database_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "database"))
    exclude_prefixes = [binaries_dir, database_dir]
    for path in paths:
        if os.path.isfile(path):
            abspath = os.path.abspath(path)
            if abspath == script_path:
                continue
            if any(abspath.startswith(prefix) for prefix in exclude_prefixes):
                continue
            file_list.append(path)
        else:
            for root, _, files in os.walk(path):
                abroot = os.path.abspath(root)
                if abroot == binaries_dir or abroot == database_dir:
                    continue
                for file in files:
                    full_path = os.path.join(root, file)
                    abspath = os.path.abspath(full_path)
                    if abspath == script_path:
                        continue
                    if any(abspath.startswith(prefix) for prefix in exclude_prefixes):
                        continue
                    if only_exec:
                        if is_pe(full_path) or is_elf(full_path):
                            file_list.append(full_path)
                    else:
                        file_list.append(full_path)
    return file_list


def save_file(src, sha256, binaries_dir):
    subdir = os.path.join(binaries_dir, sha256[:2])
    os.makedirs(subdir, exist_ok=True)
    dst = os.path.join(subdir, sha256)
    shutil.copy2(src, dst)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+", help="수집할 경로(들)")
    parser.add_argument(
        "--no-collect", action="store_true", help="파일 자체 수집 비활성화"
    )
    parser.add_argument(
        "--all", action="store_true", help="전체 파일 수집 (기본: 실행파일만)"
    )
    parser.add_argument(
        "--db", choices=["csv", "sqlite"], default="csv", help="정보 저장 방식"
    )
    parser.add_argument(
        "--keep", action="store_true", help="이전 결과를 유지(append)할지 여부"
    )
    args = parser.parse_args()

    binaries_dir = os.path.join(os.path.dirname(__file__), "binaries")
    db_dir = os.path.join(os.path.dirname(__file__), "database")
    os.makedirs(db_dir, exist_ok=True)
    if not args.no_collect:
        os.makedirs(binaries_dir, exist_ok=True)

    files = collect_files(args.paths, only_exec=not args.all)
    results = []

    for filepath in tqdm(files, desc="파일 수집 중"):
        info = {
            "filepath": filepath,
            "filename": os.path.basename(filepath),
        }
        try:
            info["size"] = os.path.getsize(filepath)
        except Exception as e:
            info["size"] = None
            info["size_error"] = str(e)
        try:
            md5, sha256 = get_file_hashes(filepath)
            info["md5"] = md5
            info["sha256"] = sha256
        except Exception as e:
            info["md5"] = None
            info["sha256"] = None
            info["hash_error"] = str(e)
        try:
            filetype = get_magic_type(filepath)
            info["filetype"] = filetype
        except Exception as e:
            info["filetype"] = None
            info["filetype_error"] = str(e)
        try:
            entropy = calc_entropy(filepath)
            info["entropy"] = entropy
        except Exception as e:
            info["entropy"] = None
            info["entropy_error"] = str(e)
        try:
            if is_pe(filepath):
                info["type"] = "PE"
                info.update(get_pe_info(filepath))
            elif is_elf(filepath):
                info["type"] = "ELF"
                info.update(get_elf_info(filepath))
            else:
                info["type"] = info.get("filetype", "UNKNOWN")
        except Exception as e:
            info["type"] = info.get("filetype", "UNKNOWN")
            info["type_error"] = str(e)
        results.append(info)
        if not args.no_collect:
            try:
                if info.get("sha256"):
                    save_file(filepath, info["sha256"], binaries_dir)
            except Exception as e:
                info["save_error"] = str(e)

    df = pd.DataFrame(results)
    if len(df) == 0:
        print(
            "\n수집된 파일이 없습니다. (실행파일이 없거나, 조건에 맞는 파일이 없습니다)"
        )
        return
    if args.db == "csv":
        csv_path = os.path.join(db_dir, "database.csv")
        file_exists = os.path.exists(csv_path)
        if args.keep and file_exists:
            df.to_csv(csv_path, mode="a", header=False, index=False)
        else:
            df.to_csv(csv_path, index=False)
    else:
        sqlite_path = os.path.join(db_dir, "database.sqlite")
        conn = sqlite3.connect(sqlite_path)
        table_exists = (
            conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='files'"
            ).fetchone()
            is not None
        )
        if args.keep and table_exists:
            df.to_sql("files", conn, if_exists="append", index=False)
        else:
            df.to_sql("files", conn, if_exists="replace", index=False)
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_sha256_path ON files(sha256, filepath)"
            )
        conn.close()

    print(f"\n총 {len(results)}개 파일 수집 완료.")
    print(df["type"].value_counts())


if __name__ == "__main__":
    main()
