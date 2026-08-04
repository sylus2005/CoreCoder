<?php
//1.SQL注入
$name = $_GET['name'];
$conn = mysqli_connect('localhost','root','123456','test_db');
$sql = "select * from users where username='$name'";
mysqli_query($conn,$sql);

//2.文件包含漏洞
$load_page = $_GET['page'];
include $load_page;

//3.XSS直接输出
echo "你的输入：".$_GET['text'];

//4.命令执行注入
$exec_cmd = $_GET['cmd'];
system($exec_cmd);

//5.硬编码后台管理员密码
$admin_pwd = "admin@666";
?>