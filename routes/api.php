<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\VigenereController; 


// Existing route for the Vigenere index page (GET /)
Route::get('/', [VigenereController::class, 'index'])->name('vigenere.index');


Route::post('/api/encrypt', [VigenereController::class, 'calculateApi']);