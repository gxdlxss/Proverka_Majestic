@echo off
color D
start https://0xcheats.net/auth/forgot/
start https://leet-cheats.ru/restore_password
start https://unicore.cloud/forum/lost-password/
start https://vanish-cheat.com/login

timeout 2
@chcp 65001
start https://oplata.info/info/
start https://funpay.com/account/login
start https://forum.majestic-rp.ru/
start https://discord.com/
start https://myactivity.google.com/myactivity?hl=ru&pli=1&q=cheat
start https://myactivity.google.com/item?q=funpay
start %appdata%\Microsoft\Windows\Recent
start https://myactivity.google.com/myactivity?q=0x
start https://myactivity.google.com/myactivity?q=leet
start https://myactivity.google.com/myactivity?q=cheats
start https://myactivity.google.com/myactivity?q=1337
start https://myactivity.google.com/myactivity?q=софт
start https://myactivity.google.com/myactivity?q=unicore
start https://myactivity.google.com/myactivity?q=amphetamine
start https://myactivity.google.com/myactivity?q=читы



@chcp 65001
@echo Выполняется поиск ahk, exe, zip, rar файлов. 
@echo Процесс может занять длительное время.
@echo После закрытия данного окна на рабочем столе появится txt файл с результатом поиска. 
@echo Начало работы - %DATE% в %TIME%. Имя пользователя компьютера: %USERNAME% 
@echo off
  setlocal enabledelayedexpansion
    for /l %%i in (65, 1, 90) do (
      cmd /c exit /b %%i
  2>nul dir /b /s !=exitcodeascii!:\*.rar>>%userprofile%\Desktop\check.txt
  2>nul dir /b /s !=exitcodeascii!:\*.zip>>%userprofile%\Desktop\check.txt
  2>nul dir /b /s !=exitcodeascii!:\*.ahk>>%userprofile%\Desktop\check.txt
  2>nul dir /b /s !=exitcodeascii!:\*.exe>>%userprofile%\Desktop\check.txt
    )
  endlocal
exit /b