<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\VigenereController;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');


Route::post('/encrypt', [VigenereController::class, 'calculateApi']);
Route::post('/decrypt', [VigenereController::class, 'decryptApi']);