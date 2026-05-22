"""pytest conftest — добавляет корень проекта в sys.path для всех тестов."""
import sys
import os

# Абсолютный путь к корню проекта
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
