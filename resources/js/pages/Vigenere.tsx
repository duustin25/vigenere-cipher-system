import { PlaceholderPattern } from '@/components/ui/placeholder-pattern';
import AppLayout from '@/layouts/app-layout';
import { dashboard } from '@/routes';
import { type BreadcrumbItem } from '@/types';
import { useForm , Head } from '@inertiajs/react';

type VigenereProps = {
    plaintext?: string;
    key?: string;
    mode?: string;
    mod?: number;
    ciphertext?: string;
    details?: Array<{
        P: string;
        Pval: number;
        K: string;
        Kval: number;
        Formula?: string;
        Result: string;
    }>;
};

const breadcrumbs: BreadcrumbItem[] = [
    {
        title: 'Vigenere Cipher',
        href: '/vigenere',
    },
];


export default function vigenere({
       plaintext = '',
        key = '',
        mode = 'encode',
        mod = 26,
        ciphertext = '',
        details = [],
    }: VigenereProps) {
        const { data, setData, post, processing, errors } = useForm<{
            plaintext: string;
            key: string;
            mode: string;
            mod: number;
        }>({
            plaintext,
            key,
            mode,
            mod,
        });

        const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();

        const alphabets = {
            26: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            27: "ABCDEFGHIJKLMNOPQRSTUVWXYZ ",
            37: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ",
        };

        const allowed = alphabets[data.mod as keyof typeof alphabets];
        const invalidKeyChar = data.key.toUpperCase().split('').find(ch => !allowed.includes(ch));
        const invalidPlainChar = data.plaintext.toUpperCase().split('').find(ch => !allowed.includes(ch));

        if (invalidKeyChar) {
            alert(`Invalid character '${invalidKeyChar}' in key for MOD ${data.mod}.`);
            return;
        }

        if (invalidPlainChar) {
            alert(`Invalid character '${invalidPlainChar}' in plaintext for MOD ${data.mod}.`);
            return;
        }

        post('/vigenere/process');
    };


    return (
        <div className="">
            <Head title="Vigenere Cipher" />

            <div className="w-4/5 max-w-7xl mx-auto py-8">
                <h1 className="text-2xl font-semibold mb-6 text-white-800">
                    Vigenère Cipher Calculator
                </h1>

                <form
                    onSubmit={handleSubmit}
                    className="grid grid-cols-1 md:grid-cols-3 gap-6"
                >
                    {/* Plaintext */}
                    <div>
                        <h2 className="font-semibold mb-2 text-white-700">Plaintext</h2>
                        <textarea
                            name="plaintext"
                            value={data.plaintext}
                            onChange={(e) => setData('plaintext', e.target.value)}
                            className="w-full h-32 border border-gray-300 rounded-md p-2 focus:ring-2 focus:ring-blue-400 focus:outline-none"
                            placeholder="Enter text"
                        />
                        {errors.plaintext && (
                            <p className="text-red-500 text-sm mt-1">{errors.plaintext}</p>
                        )}
                    </div>

                    {/* Settings */}
                    <div>
                        <h2 className="font-semibold mb-2">Settings</h2>

                        <label className="block text-sm font-medium">Key:</label>
                        <input
                            type="text"
                            name="key"
                            value={data.key}
                            onChange={(e) => setData('key', e.target.value)}
                            className="w-full border border-gray-300 rounded-md p-2 bg-gray-100 text-gray-800 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition"
                            placeholder="Enter key"
                        />
                        {errors.key && (
                            <p className="text-red-500 text-sm mt-1">{errors.key}</p>
                        )}

                        <label className="block text-sm font-medium mt-3">MOD:</label>
                        <select
                            name="mod"
                            value={data.mod}
                            onChange={(e) => setData('mod', Number(e.target.value))}
                            className="w-full border border-gray-300 rounded-md p-2 bg-gray-100 text-gray-800 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition"
                        >
                            <option value={26}>26 (A–Z)</option>
                            <option value={27}>27 (A–Z + space)</option>
                            <option value={37}>37 (A–Z + 0–9 + space)</option>
                        </select>

                        <label className="block text-sm font-medium mt-3">MODE:</label>
                        <select
                            name="mode"
                            value={data.mode}
                            onChange={(e) => setData('mode', e.target.value)}
                            className="w-full border border-gray-300 rounded-md p-2 bg-gray-100 text-gray-800 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition"
                        >
                            <option value="encode">Encode</option>
                            <option value="decode">Decode</option>
                        </select>

                        <button
                            type="submit"
                            disabled={processing}
                            className="mt-4 w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-md transition"
                        >
                            {processing ? 'Processing...' : 'Calculate'}
                        </button>
                    </div>

                    {/* Ciphertext */}
                    <div>
                        <h2 className="font-semibold mb-2 text-white-700">Ciphertext</h2>
                        <textarea
                            readOnly
                            value={ciphertext || ''}
                            className="w-full h-32 border border-gray-300 rounded-md p-2 bg-gray-100 text-gray-800 font-mono cursor-not-allowed"
                            placeholder="Result will appear here"
                        />
                    </div>
                </form>

                {/* Calculation Table */}
                {details?.length > 0 && (
                    <div className="mt-10">
                        <h2 className="text-lg font-semibold mb-3 text-white-800">
                            Calculation Details
                        </h2>
                        <div className="overflow-x-auto rounded-lg shadow border border-gray-300">
                            <table className="min-w-full text-sm bg-white">
                                <thead className="bg-gray-200 text-gray-800">
                                    <tr>
                                        <th className="border border-gray-300 px-2 py-1 text-center">#</th>
                                        <th className="border border-gray-300 px-2 py-1 text-center">P</th>
                                        <th className="border border-gray-300 px-2 py-1 text-center">Pval</th>
                                        <th className="border border-gray-300 px-2 py-1 text-center">K</th>
                                        <th className="border border-gray-300 px-2 py-1 text-center">Kval</th>
                                        <th className="border border-gray-300 px-2 py-1 text-center">Formula</th>
                                        <th className="border border-gray-300 px-2 py-1 text-center">Result</th>
                                    </tr>
                                </thead>
                                <tbody className="text-gray-700">
                                    {details.map((row, i) => (
                                        <tr
                                            key={i}
                                            className={i % 2 === 0 ? "bg-white-50" : "bg-white"}
                                        >
                                            <td className="border border-gray-300 px-2 py-1 text-center">{i + 1}</td>
                                            <td className="border border-gray-300 px-2 py-1 text-center">{row.P}</td>
                                            <td className="border border-gray-300 px-2 py-1 text-center">{row.Pval}</td>
                                            <td className="border border-gray-300 px-2 py-1 text-center">{row.K}</td>
                                            <td className="border border-gray-300 px-2 py-1 text-center">{row.Kval}</td>
                                            <td className="border border-gray-300 px-2 py-1 text-center">
                                                {row.Formula}
                                            </td>
                                            <td className="border border-gray-300 px-2 py-1 text-center font-semibold">
                                                {row.Result}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                )}
            </div>

            <div className="w-4/5 max-w-6xl mx-auto py-8">

                {/* ✅ Historical + Documentation Section */}
                <h2 className="text-2xl font-semibold mb-3">History of the Vigenère Cipher</h2>
                <p className="mb-4">
                    The Vigenère Cipher was first introduced in 1553 by Italian cryptographer
                    Giovan Battista Bellaso. It applied a repeating keyword to shift characters
                    in the plaintext, making it more secure than earlier substitution ciphers.
                    Later, Blaise de Vigenère published an improved method using a{" "}
                    <strong>tabula recta</strong>, and the cipher eventually became known under
                    his name.
                </p>

                {/* Image Section */}
                <div className="my-6 flex justify-center">
                    <img
                    src="/images/vigenere.png"
                    alt="Vigenère Cipher Chart"
                    className="w-[350px] h-[300px]  rounded-lg shadow-md"
                    />
                </div>
  
                <p className="mb-6">
                    For centuries, the cipher was believed to be unbreakable, known as the{" "}
                    <strong>“Indecipherable Cipher”</strong>. In the 1800s, Charles Babbage and
                    Friedrich Kasiski developed techniques to break it through keyword length
                    discovery and frequency analysis. This marked a significant breakthrough in
                    cryptanalysis.
                </p>

                <h2 className="text-2xl font-semibold mb-3">How the Classical Vigenère Cipher Works</h2>
                <p className="mb-4">
                    Traditionally operating on the 26 English letters (A–Z), each letter is
                    converted into a number: A=0, B=1, … Z=25. Using{" "}
                    <strong>mod 26 arithmetic</strong>:
                </p>
                <p className="mb-4">
                    <strong>Encryption:</strong> C = (P + K) mod 26 <br />
                    <strong>Decryption:</strong> P = (C − K + 26) mod 26
                </p>
                <p className="mb-6">
                    The repeated keyword creates multiple Caesar shifts, making frequency
                    attacks more difficult compared to simple substitution ciphers.
                </p>


                <p className="italic">
                    Example image:
                </p>

                {/* Image Section */}
                <div className="my-6 flex justify-center">
                    <img
                    src="/images/vigenere-chart.png"
                    alt="Vigenère Cipher Chart"
                    className="w-[1000px] h-[500px]  rounded-lg shadow-md"
                    />
                </div>

                <h2 className="text-2xl font-semibold mb-3">Extended Vigenère Using Mod 37</h2>
                <p className="mb-4">
                    To support more modern communication, the Vigenère Cipher can be extended
                    beyond letters to include: <strong>A–Z, 0–9, and a space</strong>. This
                    creates a 37-character set and uses:
                </p>
                <p className="mb-4">
                    <strong>Formula:</strong> C = (P + K) mod 37
                </p>
                <p className="mb-6">
                    This version is especially useful for numeric codes, aviation text, and
                    digital identifiers — enhancing security and flexibility while still
                    preserving Vigenère's classical logic.
                </p>

                <p className="italic">
                    Even though computers can break Vigenère today, it remains a cornerstone of
                    classical cryptography and a key foundation for modern encryption
                    principles.
                </p>
            </div>





        </div>
    );
}
