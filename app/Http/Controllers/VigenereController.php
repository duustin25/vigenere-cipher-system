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
                 $validationError = ['plaintext' => "Invalid character '{$ch}' in input text. Allowed: {$modLabel}."];
                 return ['', [], $validationError];
             }
        }


        // --- Cipher Computation ---
        $resultText = ''; // Renamed to be generic (plaintext or ciphertext)
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

            // Core Logic: Addition for Encode, Subtraction for Decode
            $cVal = $mode === 'encode'
                ? ($pVal + $kVal) % $mod
                : ($pVal - $kVal + $mod) % $mod;

            $cChar = $alphabet[$cVal];
            $resultText .= $cChar;

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

        return [$resultText, $details, null]; // Success: return resultText (ciphertext or plaintext), details, no error
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
        [$resultText, $details, $error] = $this->runCipherCalculation($plaintext, $key, $mode, $mod);
        
        // We ensure 'plaintext' is the *input* text and 'ciphertext' is the *output* text for the session
        if ($mode === 'decode') {
            $plaintext = $resultText; // The decrypted result is the new plaintext for display
            $ciphertext = strtoupper($validated['plaintext']); // The original input was the ciphertext
        } else {
             $ciphertext = $resultText;
        }

        if ($error) {
            // Revert back to original request names for back() redirect
             return back()->withErrors($error)->withInput();
        }

        return redirect()->route('vigenere.index')->with( [
            'plaintext'  => $plaintext, // The final plaintext (input or output)
            'key'        => $key,
            'mode'       => $mode,
            'mod'        => $mod,
            'ciphertext' => $ciphertext, // The final ciphertext (input or output)
            'details'    => $details,
        ]);
    }


    /**
     * 🚀 API Endpoint: Receives POST request from n8n (mapped to /api/encrypt).
     * It expects 'plainText', 'key', and 'mod' from the n8n JSON body.
     */
    public function calculateApi(Request $request): JsonResponse
    {
        // 1. Validate API-specific parameters
        $validated = $request->validate([
            'plainText' => 'nullable|string',
            'key'       => 'required|string',
            'mod'       => 'required|integer|min:1|max:200',
        ]);

        $plaintext = strtoupper($validated['plainText'] ?? '');
        $key       = strtoupper($validated['key']);
        // Hardcode 'encode' for this API mode
        $mode      = 'encode';
        $mod       = (int) $validated['mod'];

      
        // The result will be the ciphertext
        [$ciphertext, $details, $error] = $this->runCipherCalculation($plaintext, $key, $mode, $mod);

        // 3. Handle Errors (Return a 400 Bad Request if validation/cipher logic fails)
        if ($error) {
             return response()->json([
                'status' => 'error',
                'message' => 'Input validation failed during cipher calculation.',
                'errors' => $error,
            ], 400);
        }

        // 4. Return Success
        return response()->json([
            'status' => 'success',
            'ciphertext' => $ciphertext,
        ], 200);
    }


    /**
     * 🔓 API Endpoint: Receives POST request for Decryption (mapped to /api/decrypt).
     * It expects 'ciphertext', 'key', and 'mod' from the JSON body.
     */
    public function decryptApi(Request $request): JsonResponse
    {
        // 1. Validate API-specific parameters
        $validated = $request->validate([
            // We expect 'ciphertext' (encrypted text) for decryption
            'ciphertext' => 'nullable|string',
            'key'        => 'required|string',
            'mod'        => 'required|integer|min:1|max:200',
        ]);

        $ciphertext = strtoupper($validated['ciphertext'] ?? '');
        $key        = strtoupper($validated['key']);
        // CRITICAL: Set the mode to 'decode' for decryption
        $mode       = 'decode'; 
        $mod        = (int) $validated['mod'];

        // 2. Run the decryption calculation. The result is the plaintext.
        [$plaintext, $details, $error] = $this->runCipherCalculation($ciphertext, $key, $mode, $mod);

        // 3. Handle Errors (Return a 400 Bad Request if validation/cipher logic fails)
        if ($error) {
             return response()->json([
                'status' => 'error',
                'message' => 'Input validation failed during cipher calculation.',
                'errors' => $error,
            ], 400);
        }

        // 4. Return Success (Returns clean JSON with the decrypted text)
        return response()->json([
            'status' => 'success',
            // Return the decrypted text in the 'plaintext' field
            'plaintext' => $plaintext,
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