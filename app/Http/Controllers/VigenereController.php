<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Inertia\Inertia;


class VigenereController extends Controller
{
    /**
     * Show the Vigenère cipher calculator page.
     */
    public function index()
    {
        return Inertia::render('Vigenere', [
            'plaintext'  => session('plaintext', ''),
            'key'        => session('key', ''),
            'mode'       => session('mode', 'encode'),
            'mod'        => session('mod', 26),
            'ciphertext' => session('ciphertext', ''),
            'details'    => session('details', []),
        ]);
    }

    /**
     * Process the Vigenère cipher calculation.
     */
public function process(Request $request)
{
    $request->validate([
        'plaintext' => 'nullable|string',
        'key'       => 'required|string',
        'mode'      => 'required|in:encode,decode',
        'mod'       => 'required|integer|min:1|max:200',
    ]);

    $plaintext = strtoupper($request->plaintext ?? '');
    $key       = strtoupper($request->key);
    $mode      = $request->mode;
    $mod       = (int) $request->mod;

    // --- Select alphabet based on MOD ---
    switch ($mod) {
        case 26:
            $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            $modLabel = "A–Z only";
            break;
        case 27:
            $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";
            $modLabel = "A–Z and space only";
            break;
        case 37:
            $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
            $modLabel = "A–Z, 0–9, and space only";
            break;
        default:
            return back()->withErrors(['mod' => "Unsupported MOD value: $mod"])->withInput();
    }

    // --- Validate characters in key ---
    foreach (str_split($key) as $ch) {
        if (strpos($alphabet, $ch) === false) {
            return back()->withErrors([
                'key' => "Invalid character '{$ch}' in key. Allowed: {$modLabel}."
            ])->withInput();
        }
    }

    // --- Validate characters in plaintext ---
    foreach (str_split($plaintext) as $ch) {
        if (strpos($alphabet, $ch) === false) {
            return back()->withErrors([
                'plaintext' => "Invalid character '{$ch}' in plaintext. Allowed: {$modLabel}."
            ])->withInput();
        }
    }

    // --- Cipher Computation ---
    $ciphertext = '';
    $details    = [];
    $keyIndex   = 0;
    $keyLength  = strlen($key);

    for ($i = 0; $i < strlen($plaintext); $i++) {
        $pChar = $plaintext[$i];
        if (strpos($alphabet, $pChar) === false) continue;

        $pVal  = strpos($alphabet, $pChar);
        $kChar = $key[$keyIndex % $keyLength];
        $kVal  = strpos($alphabet, $kChar);
        $keyIndex++;

        $cVal = $mode === 'encode'
            ? ($pVal + $kVal) % $mod
            : ($pVal - $kVal + $mod) % $mod;

        $cChar = $alphabet[$cVal];
        $ciphertext .= $cChar;

        $formula = $mode === 'encode'
        ? "($pVal + $kVal) mod $mod = $cVal"
        : "($pVal - $kVal + $mod) mod $mod = $cVal";

        $details[] = [
            'P' => $pChar,
            'Pval' => $pVal,
            'K' => $kChar,
            'Kval' => $kVal,
            'Formula' => $formula,  
            'Result' => $cChar,
        ];
    }

    return redirect()->route('vigenere.index')->with( [
        'plaintext'  => $plaintext,
        'key'        => $key,
        'mode'       => $mode,
        'mod'        => $mod,
        'ciphertext' => $ciphertext,
        'details'    => $details,
    ]);
}

    /**
     * (Optional) Separate result page — not currently used, but kept for flexibility.
     */
    public function result()
    {
        return Inertia::render('vigenereResult', [
            'plaintext'  => session('plaintext'),
            'key'        => session('key'),
            'mode'       => session('mode'),
            'mod'        => session('mod'),
            'ciphertext' => session('ciphertext'),
            'details'    => session('details'),
        ]);
    }
}
