@echo off
cd /d "%USERPROFILE%\mgtransfertool\venv\Scripts"
call activate.bat
cd /d "%USERPROFILE%\mgtransfertool"
python -m tksample1
