@echo off
chcp 65001

REM 注意：date 和 time 格式因系統語言不同可能會有差異，這是一個常見格式的範例
set COMMIT_MSG=%date%_%time%_update

echo 使用提交訊息：%COMMIT_MSG%

REM 固定遠端名稱
set REMOTE_NAME=origin 

REM 取得當前分支名稱
for /f %%b in ('git branch --show-current') do set BRANCH_NAME=%%b
echo 當前分支名稱：%BRANCH_NAME%

echo 添加所有變更...
git add .

echo 提交變更...
git commit -m "%COMMIT_MSG%"

echo 推送到遠端 %REMOTE_NAME% 的 %BRANCH_NAME% 分支...
git push %REMOTE_NAME% %BRANCH_NAME%

echo 完成！
pause