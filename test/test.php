<?php

require ('../vendor/autoload.php');

use Inn\Jwt;

$jwt = new Jwt('SECRET');
$jwt->notBefore = time() + 3;
$jwt->expires = time() + 6;

$token = $jwt->encode([
    'id' => 1,
    'name' => 'izisaurio',
    'email' => 'izi.isaac@gmail.com'
]);

var_dump($token);

$decoded = $jwt->decode($token);

var_dump($decoded);

var_dump($decoded->validate());

sleep(4);

var_dump($decoded->validate());

sleep(4);

var_dump($decoded->validate());