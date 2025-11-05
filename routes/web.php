<?php

use Illuminate\Support\Facades\Route;
use Inertia\Inertia;
use Laravel\Fortify\Features;
use App\Http\Controllers\VigenereController;

Route::get('/home', function () {
    return Inertia::render('welcome', [
        'canRegister' => Features::enabled(Features::registration()),
    ]);
})->name('home');

Route::middleware(['auth', 'verified'])->group(function () {
    Route::get('dashboard', function () {
        return Inertia::render('dashboard');
    })->name('dashboard');
});

//api route
Route::post('/api/encrypt', [VigenereController::class, 'calculateApi']);
Route::get('/', [VigenereController::class, 'index'])->name('vigenere.index');
Route::post('/vigenere/process', [VigenereController::class, 'process'])->name('vigenere.process');
Route::get('/vigenere/result', [VigenereController::class, 'result'])->name('vigenere.result');


require __DIR__.'/settings.php';
