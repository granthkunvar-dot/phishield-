@echo off
REM ==============================================================================
REM Phishield Runner for Windows
REM ==============================================================================

if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
)

python run.py
pause

