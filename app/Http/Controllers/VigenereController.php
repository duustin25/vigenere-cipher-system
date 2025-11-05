<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Inertia\Inertia;
use Illuminate\Http\JsonResponse; 

class VigenereController extends Controller
{
    /**
     * Helper function to contain the core cipher logic, used by both web and API modes.
     * This prevents code duplication.
     * @param string $plaintext - The input text to be encrypted/decrypted.
     * @param string $key - The key for the Vigenere cipher.
     * @param string $mode - 'encode' or 'decode'.
     * @param int $mod - The modulus value (e.g., 26, 27, 37).
     * @return array - [ciphertext, details, error]
     */
    private function runCipherCalculation(string $plaintext, string $key, string $mode, int $mod): array
    {
        // Core checks
        if ($mod < 1) {
            return ['', [], ['mod' => "The MOD value must be greater than 0."]];
        }

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
                return ['', [], ['mod' => "Unsupported MOD value: $mod. Only 26, 27, 37 are supported for Vigenère."]];
        }

        // --- Validation: Ensure key and plaintext characters are in the alphabet ---
        $validationError = null;
        // We only check characters that are part of the alphabet for both key and plaintext
        $keyChars = str_split($key);
        $plainTextChars = str_split($plaintext);

        foreach ($keyChars as $ch) {
            if (strpos($alphabet, $ch) === false) {
                 $validationError = ['key' => "Invalid character '{$ch}' in key. Allowed: {$modLabel}."];
                 return ['', [], $validationError];
            }
        }
        
        foreach ($plainTextChars as $ch) {
             if (strpos($alphabet, $ch) === false) {
                 $validationError = ['plaintext' => "Invalid character '{$ch}' in plaintext. Allowed: {$modLabel}."];
                 return ['', [], $validationError];
            }
        }


        // --- Cipher Computation ---
        $ciphertext = '';
        $details    = [];
        $keyIndex   = 0;
        $keyLength  = strlen($key);

        for ($i = 0; $i < strlen($plaintext); $i++) {
            $pChar = $plaintext[$i];
            if (strpos($alphabet, $pChar) === false) continue; // Should not happen due to validation, but good practice

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

        return [$ciphertext, $details, null]; // Success: return ciphertext, details, no error
    }

    /**
     * Show the Vigenère cipher calculator page (for standard browser access).
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
     * Process the Vigenère cipher calculation (for browser POST).
     */
    public function process(Request $request)
    {
        $validated = $request->validate([
            'plaintext' => 'nullable|string',
            'key'       => 'required|string',
            'mode'      => 'required|in:encode,decode',
            'mod'       => 'required|integer|min:1|max:200',
        ]);

        $plaintext = strtoupper($validated['plaintext'] ?? '');
        $key       = strtoupper($validated['key']);
        $mode      = $validated['mode'];
        $mod       = (int) $validated['mod'];

        // Use the new helper function
        [$ciphertext, $details, $error] = $this->runCipherCalculation($plaintext, $key, $mode, $mod);

        if ($error) {
            // Revert back to original request names for back() redirect
             return back()->withErrors($error)->withInput();
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
     * 🚀 API Endpoint: Receives POST request from n8n (mapped to /api/encrypt).
     * It expects 'plainText', 'key', and 'mod' from the n8n JSON body.
     */
    public function calculateApi(Request $request): JsonResponse
    {
        // 1. Validate API-specific parameters (using lowerCamelCase from the front-end)
        $validated = $request->validate([
            'plainText' => 'nullable|string',
            'key'       => 'required|string',
            'mod'       => 'required|integer|min:1|max:200',
        ]);

        $plaintext = strtoupper($validated['plainText'] ?? '');
        $key       = strtoupper($validated['key']);
        // The front-end app is an encryption form, so we hardcode 'encode' for the API mode
        $mode      = 'encode';
        $mod       = (int) $validated['mod'];

        // 2. Run the core calculation logic
        [$ciphertext, $details, $error] = $this->runCipherCalculation($plaintext, $key, $mode, $mod);

        // 3. Handle Errors (Return a 400 Bad Request if validation/cipher logic fails)
        if ($error) {
             return response()->json([
                'status' => 'error',
                'message' => 'Input validation failed during cipher calculation.',
                'errors' => $error,
            ], 400);
        }

        // 4. Return Success (Returns clean JSON to n8n)
        return response()->json([
            'status' => 'success',
            // CRITICAL: This is the field n8n and the front-end are expecting
            'ciphertext' => $ciphertext,
        ], 200);
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