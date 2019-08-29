<?php
echo 1;
date_default_timezone_set('Asia/Shanghai');

$fh = fopen("referer.txt", "a");

$ip        = $_SERVER["REMOTE_ADDR"];   //访问IP 
$filename  = $_SERVER['PHP_SELF'];  //访问的文件  
$parameter = $_SERVER["QUERY_STRING"];  //查询的字符串  
$method    = $_SERVER['REQUEST_METHOD']; //请求方法  
$time      =  date('Y-m-d H:i:s',time()); //请求时间  
$post      = '';
$get       = $filename.'?'.$parameter;
$others    = '**********************************************************************';  
if($method == 'GET')
{
	$logadd    = 'TIME:'.$time."\r\n".'IP:'.$ip.' '.'URL:'.$filename.'?'.$parameter."\r\n".'cookie:';
}
if($method == 'POST') {
	$post      = file_get_contents("php://input",'r'); //接收数据 
	$logadd    = 'TIME:'.$time."\r\n".'IP:'.$ip.' '.'URL:'.$filename.'?'.$parameter."\r\n".'METHOD:'.$method.' '.'DATA:'.$post."\r\n".'cookie:';
}

fwrite($fh, $logadd);
fwrite($fh,"\r\n");
if(isset($_SERVER['HTTP_X_FORWARDED_FOR'])){
	fwrite($fh,"X_Forwarded_For:");
	fwrite($fh,var_export($_SERVER['HTTP_X_FORWARDED_FOR'], true)."\r\n");
}
if(isset($_SERVER['HTTP_REFERER'])){
	fwrite($fh,"Referer:");
	fwrite($fh,var_export($_SERVER['HTTP_REFERER'], true)."\r\n");
}
if(isset($_SERVER['HTTP_USER_AGENT'])){
	fwrite($fh,"USER_AGENT:");
	fwrite($fh,var_export($_SERVER['HTTP_USER_AGENT'], true)."\r\n");
}
fwrite($fh,$others."\r\n");
?>