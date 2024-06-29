@echo off
"%LOCALAPPDATA%\Programs\Python\Python312\Scripts\pip" install virtualenv
cd /d "%USERPROFILE%"
mkdir mgtransfertool
cd mgtransfertool
"%LOCALAPPDATA%\Programs\Python\Python312\Scripts\virtualenv" venv

cd /d "%USERPROFILE%\mgtransfertool\venv\Scripts"
call activate.bat

cd /d "%USERPROFILE%\mgtransfertool"
pip install -r requirements.txt
