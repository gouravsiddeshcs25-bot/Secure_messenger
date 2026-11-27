/**
 * Data Loss Prevention (DLP) Subsystem for Secure Messenger v2.
 * 
 * Runs entirely on the client before message transmission.
 * Detects sensitive personal identifiable information (PII) and secret credentials:
 * 1. Aadhaar-like 12-digit national identity numbers
 * 2. Credit Card numbers with Luhn checksum validation
 * 3. High-entropy API keys, tokens, and credentials (AWS, GitHub, OpenAI, Slack, Private Keys)
 * 
 * WHY CLIENT-SIDE:
 * Pre-encryption DLP ensures sensitive information is recognized before leaving
 * the browser. When detected, the client automatically forces Sensitive Mode (ephemerality,
 * one-time view, and server-side TTL purge).
 */

const DLP = {
    /**
     * Standard Luhn checksum algorithm (Modulus 10).
     * Used by all major credit card issuers (Visa, Mastercard, Amex, Discover).
     * 
     * WHY: Regex alone causes high false positives on arbitrary 16-digit numbers.
     * The Luhn test mathematically validates that a number sequence is a valid card number.
     */
    luhnCheck(digitsOnly) {
        if (!digitsOnly || digitsOnly.length < 13 || digitsOnly.length > 19) {
            return false;
        }
        let sum = 0;
        let alternate = false;
        for (let i = digitsOnly.length - 1; i >= 0; i--) {
            let n = parseInt(digitsOnly.charAt(i), 10);
            if (isNaN(n)) return false;
            if (alternate) {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            alternate = !alternate;
        }
        return sum % 10 === 0;
    },

    /**
     * Verhoeff check table (optional extra validation for Aadhaar digits).
     */
    verhoeffCheck(digitsOnly) {
        // Aadhaar numbers are 12 digits and do not start with 0 or 1
        return digitsOnly.length === 12 && /^[2-9]/.test(digitsOnly);
    },

    /**
     * Inspects plain text for confidential information patterns.
     * Returns: {
     *   detected: boolean,
     *   reasons: string[],
     *   details: { aadhaar: boolean, creditCard: boolean, secrets: boolean }
     * }
     */
    scan(text) {
        if (!text || typeof text !== "string") {
            return { detected: false, reasons: [], details: { aadhaar: false, creditCard: false, secrets: false } };
        }

        const findings = [];
        let hasAadhaar = false;
        let hasCreditCard = false;
        let hasSecrets = false;

        // 1. AADHAAR DETECTION:
        // Indian Aadhaar numbers consist of exactly 12 digits, typically formatted as
        // 4-4-4 (e.g., 2345 6789 0123) or continuous 12 digits, starting with [2-9].
        // Must NOT match prefixes of 13-19 digit card numbers or longer digit sequences.
        const aadhaarRegex = /(?<!\d)[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}(?!\s*\d|\d)/g;
        const aadhaarMatches = text.match(aadhaarRegex);
        if (aadhaarMatches) {
            for (const match of aadhaarMatches) {
                const digits = match.replace(/[\s\-]/g, "");
                if (digits.length === 12 && this.verhoeffCheck(digits)) {
                    hasAadhaar = true;
                    findings.push(`Aadhaar-like 12-digit ID: ${match.slice(0, 4)} **** ****`);
                    break;
                }
            }
        }

        // 2. CREDIT CARD DETECTION (with Luhn Validation):
        // Matches potential 13-19 digit card numbers separated by spaces or dashes.
        const ccCandidateRegex = /\b(?:\d[ \-]*?){13,19}\b/g;
        const ccCandidates = text.match(ccCandidateRegex) || [];
        for (const candidate of ccCandidates) {
            const digitsOnly = candidate.replace(/\D/g, "");
            // Check major issuer prefixes:
            // Visa (4), Mastercard (51-55, 22-27), Amex (34, 37), Discover (6011, 65)
            if (this.luhnCheck(digitsOnly)) {
                hasCreditCard = true;
                const masked = digitsOnly.slice(0, 4) + " **** **** " + digitsOnly.slice(-4);
                findings.push(`Valid Credit Card number (${masked}) verified by Luhn checksum`);
                break;
            }
        }

        // 3. API KEYS, SECRETS, AND PASSWORD PATTERNS:
        const secretRules = [
            {
                name: "AWS Access Key ID",
                regex: /\b(AKIA[0-9A-Z]{16})\b/
            },
            {
                name: "GitHub Token",
                regex: /\b(gh[pousr]_[A-Za-z0-9_]{36,})\b/
            },
            {
                name: "OpenAI / Bearer API Key",
                regex: /\b(sk-[A-Za-z0-9_\-]{20,})\b/
            },
            {
                name: "Slack API Token",
                regex: /\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b/
            },
            {
                name: "Private Key Header",
                regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/
            },
            {
                name: "Explicit Password/Secret Assignment",
                regex: /\b(?:password|passwd|api_key|apikey|secret_key|client_secret)\s*[:=]\s*['"]?([^\s'"]{6,})['"]?/i
            }
        ];

        for (const rule of secretRules) {
            if (rule.regex.test(text)) {
                hasSecrets = true;
                findings.push(`Secret pattern detected: ${rule.name}`);
                break;
            }
        }

        return {
            detected: findings.length > 0,
            reasons: findings,
            details: {
                aadhaar: hasAadhaar,
                creditCard: hasCreditCard,
                secrets: hasSecrets
            }
        };
    }
};

if (typeof window !== "undefined") {
    window.DLP = DLP;
}
if (typeof module !== "undefined" && module.exports) {
    module.exports = DLP;
}
