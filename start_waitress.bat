@echo off
set VENV_PATH=C:\Users\User\Desktop\redmine-api-management\venv
set APP_PATH=C:\Users\User\Desktop\redmine-api-management

call %VENV_PATH%\Scripts\activate.bat
python %APP_PATH%\wsgi.py
pause
