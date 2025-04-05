/* static/script.js */
document.addEventListener('DOMContentLoaded', () => {
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const togglePasswordButton = document.getElementById('togglePassword');
    const checkStrengthButton = document.getElementById('checkStrengthButton');
    const hashButton = document.getElementById('hashButton');
    const encryptButton = document.getElementById('encryptButton');
    const decryptButton = document.getElementById('decryptHash');

    const strengthScoreEl = document.getElementById('strength-score');
    const strengthFeedbackEl = document.getElementById('strength-feedback');
    const strengthBar = document.getElementById('strength-bar');

    const hashingSection = document.getElementById('hashing-section');
    const hashedPasswordEl = document.getElementById('hashed-password');

    const encryptionSection = document.getElementById('encryption-section');
    const encryptionIvEl = document.getElementById('encryption-iv');
    const encryptedDataEl = document.getElementById('encrypted-data');
    const encryptionKeyEl = document.getElementById('encryption-key');

    const decryptionSection = document.getElementById('decryption-section');
    const decryptedHashEl = document.getElementById('decrypted-hash');
    const verificationResultEl = document.getElementById('verification-result');

    const errorMessageEl = document.getElementById('error-message');
    const successMessageEl = document.getElementById('success-message');

    const hashStepAsciiEl = document.getElementById('hash-step-ascii');
    const hashStepPaddingEl = document.getElementById('hash-step-padding');
    const hashStepChunksEl = document.getElementById('hash-step-chunks');

    // Decryption step elements
    const decryptStepIvEl = document.getElementById('decrypt-step-iv');
    const decryptStepDataEl = document.getElementById('decrypt-step-data');
    const decryptStepKeyEl = document.getElementById('decrypt-step-key');
    const verifyOriginalHashEl = document.getElementById('verify-original-hash');
    const verifyDecryptedHashEl = document.getElementById('verify-decrypted-hash');

    const processProgressBar = document.getElementById('process-progress');
    const hashProgressBar = document.getElementById('hash-progress');
    const encryptProgressBar = document.getElementById('encrypt-progress');
    const decryptProgressBar = document.getElementById('decrypt-progress');

    let currentHashedPassword = '';
    let currentEncryptionResult = null;

    // --- Utility Functions ---
    function displayError(message) {
        errorMessageEl.textContent = message;
        errorMessageEl.style.display = 'block';
        successMessageEl.style.display = 'none';
    }

    function displaySuccess(message) {
        successMessageEl.textContent = message;
        successMessageEl.style.display = 'block';
        errorMessageEl.style.display = 'none';
    }

    function clearMessages() {
        errorMessageEl.style.display = 'none';
        errorMessageEl.textContent = '';
        successMessageEl.style.display = 'none';
        successMessageEl.textContent = '';
    }

    function resetResults() {
        hashingSection.style.display = 'none';
        encryptionSection.style.display = 'none';
        decryptionSection.style.display = 'none';
        hashedPasswordEl.textContent = 'Not generated yet.';
        encryptionIvEl.textContent = 'Not generated yet.';
        encryptedDataEl.textContent = 'Not generated yet.';
        encryptionKeyEl.textContent = 'Not generated yet.';
        decryptedHashEl.textContent = 'Not decrypted yet.';
        verificationResultEl.textContent = '';
        decryptButton.disabled = true;
        currentHashedPassword = '';
        currentEncryptionResult = null;

        // Clear conceptual steps
        hashStepAsciiEl.textContent = '...';
        hashStepPaddingEl.textContent = '[ASCII Hex] + 80 + 00...00 + [Length]';
        hashStepChunksEl.textContent = 'Chunk 1: ...\nChunk 2: ...';
        decryptStepIvEl.textContent = '...';
        decryptStepDataEl.textContent = '...';
        decryptStepKeyEl.textContent = '...';
        verifyOriginalHashEl.textContent = '...';
        verifyDecryptedHashEl.textContent = '...';
        processProgressBar.style.display = 'none'; // Hide progress bar
        hashProgressBar.style.display = 'none'; // Hide progress bar
        encryptProgressBar.style.display = 'none'; // Hide progress bar
        decryptProgressBar.style.display = 'none'; // Hide progress bar
        hashButton.disabled = true; // Disable hash button
        encryptButton.disabled = true; // Disable encrypt button
        decryptButton.disabled = true; // Keep decrypt button disabled
    }

    function updateStrengthUI(score, feedback) {
        strengthScoreEl.textContent = `Score: ${score}/4`;
        strengthFeedbackEl.textContent = feedback;
        strengthBar.style.width = `${(score / 4) * 100}%`;
        // Remove previous strength classes and add the current one
        strengthBar.className = 'strength-bar-fill'; // Reset classes
        strengthBar.classList.add(`strength-${score}`);
        // Disable buttons by default, enable if strong
        hashButton.disabled = true;
        if (score >= 4) {
            hashButton.disabled = false;
            displaySuccess('Password is strong enough for hashing.'); // Optional feedback
        }
    }

    // --- Conceptual Step Generation ---
    function getAsciiHex(str) {
        return Array.from(str)
            .map(char => char.charCodeAt(0).toString(16).padStart(2, '0'))
            .join(' ');
    }

    function displayHashingSteps(password, finalHash) {
        const asciiHex = getAsciiHex(password);
        hashStepAsciiEl.textContent = asciiHex || '[Empty Password]';

        // Simplified Padding visualization
        const originalLengthBits = password.length * 8;
        const lengthHex = originalLengthBits.toString(16).padStart(16, '0'); // 64-bit length
        hashStepPaddingEl.textContent = `[${asciiHex || ' '}] + 80 + [Zero Padding] + ${lengthHex}`;

        // Simplified Chunk visualization (Show first ~16 bytes as hex)
        const chunk1Hex = asciiHex.split(' ').slice(0, 64).join(' '); // Show up to 64 bytes
        hashStepChunksEl.textContent = `Chunk 1 (first 64 bytes): ${chunk1Hex || ' '}${password.length > 64 ? '...' : ''}`;

        // Update the final hash display as well
        hashedPasswordEl.textContent = finalHash;

    }

    function displayDecryptionSteps(iv, encryptedData, key, decryptedHash, originalHash) {
        decryptStepIvEl.textContent = iv;
        decryptStepDataEl.textContent = encryptedData;
        decryptStepKeyEl.textContent = key;
        decryptedHashEl.textContent = decryptedHash; // Show the result from decryption
        verifyOriginalHashEl.textContent = originalHash;
        verifyDecryptedHashEl.textContent = decryptedHash;
    }

    // --- Event Listeners ---
    passwordInput.addEventListener('input', async () => {
        clearMessages();
        resetResults();
        const password = passwordInput.value;
        const username = usernameInput.value;

        if (!password) {
            updateStrengthUI(0, 'Enter a password to check its strength.');
            return;
        }

        try {
            const response = await fetch('/api/check_strength', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ password, username }),
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            updateStrengthUI(data.score, data.feedback);

        } catch (error) {
            console.error('Error checking strength:', error);
            displayError(`Error checking strength: ${error.message}`);
            updateStrengthUI(0, 'Error checking strength.');
        }
    });

    checkStrengthButton.addEventListener('click', async () => {
        clearMessages();
        resetResults(); // Reset results when explicitly checking strength
        const password = passwordInput.value;
        const username = usernameInput.value;

        if (!password) {
            displayError('Please enter a password to check.');
            updateStrengthUI(0, 'Enter a password to check its strength.');
            return;
        }

        checkStrengthButton.disabled = true;
        checkStrengthButton.textContent = 'Checking...';
        processProgressBar.style.display = 'block'; // Reuse process bar for strength check

        try {
            // Call the existing strength check API
            const response = await fetch('/api/check_strength', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password, username }),
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            updateStrengthUI(data.score, data.feedback);
            if(data.score < 4) {
                displayError("Password is not strong enough for hashing.");
            }

        } catch (error) {
             console.error('Error checking strength:', error);
            displayError(`Strength check failed: ${error.message}`);
            updateStrengthUI(0, 'Error checking strength.'); // Reset UI on error
        } finally {
            checkStrengthButton.disabled = false;
            checkStrengthButton.textContent = 'Check Strength';
            processProgressBar.style.display = 'none';
        }
    });

    hashButton.addEventListener('click', async () => {
        clearMessages();
        const password = passwordInput.value;
        if (!password) {
            displayError('Password field is empty.');
            return;
        }

        hashButton.disabled = true;
        hashButton.textContent = 'Hashing...';
        hashProgressBar.style.display = 'block';
        hashingSection.style.display = 'none'; // Hide section until done
        encryptButton.disabled = true; // Ensure encrypt is disabled
        encryptionSection.style.display = 'none'; // Hide encryption section

        try {
             const response = await fetch('/api/hash', { // New API endpoint
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ password }), // Only send password
            });

             const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || `HTTP error! status: ${response.status}`);
            }

            currentHashedPassword = data.hashed_password;
            displayHashingSteps(password, currentHashedPassword);
            hashingSection.style.display = 'block';
            encryptButton.disabled = false; // Enable encrypt button
            displaySuccess('Password hashed successfully.');

        } catch (error) {
            console.error('Error hashing password:', error);
            displayError(`Hashing failed: ${error.message}`);
             resetResults(); // Reset if hashing fails
        } finally {
            hashButton.textContent = 'Hash Password';
            hashButton.disabled = false; // Re-enable perhaps?
            hashProgressBar.style.display = 'none';
        }
    });

    encryptButton.addEventListener('click', async () => {
        clearMessages();
        if (!currentHashedPassword) {
            displayError('No hashed password available to encrypt.');
            return;
        }

        encryptButton.disabled = true;
        encryptButton.textContent = 'Encrypting...';
        encryptProgressBar.style.display = 'block';
        encryptionSection.style.display = 'none'; // Hide until done
        decryptButton.disabled = true; // Ensure decrypt is disabled

        try {
            const response = await fetch('/api/encrypt_hash', { // Renamed API endpoint
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ hash_value: currentHashedPassword }), // Send hash
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || `HTTP error! status: ${response.status}`);
            }

            currentEncryptionResult = data.encryption;
            encryptionIvEl.textContent = currentEncryptionResult.iv;
            encryptedDataEl.textContent = currentEncryptionResult.encrypted_data;
            encryptionKeyEl.textContent = currentEncryptionResult.key;
            encryptionSection.style.display = 'block';
            decryptButton.disabled = false; // Enable decrypt button
            displaySuccess('Hash encrypted successfully.');

        } catch (error) {
            console.error('Error encrypting hash:', error);
            displayError(`Encryption failed: ${error.message}`);
            // Reset encryption/decryption sections if encryption fails
            encryptionSection.style.display = 'none';
            decryptionSection.style.display = 'none';
            currentEncryptionResult = null;
            decryptButton.disabled = true;
        } finally {
             encryptButton.textContent = 'Encrypt Hash';
             encryptButton.disabled = false; // Re-enable perhaps?
             encryptProgressBar.style.display = 'none';
        }
    });

    decryptButton.addEventListener('click', async () => {
        clearMessages();
        if (!currentEncryptionResult) {
            displayError('No encrypted data available to decrypt.');
            return;
        }

        decryptButton.disabled = true;
        decryptButton.textContent = 'Decrypting...';
        decryptProgressBar.style.display = 'block'; // Show decrypt progress bar
        decryptedHashEl.textContent = 'Processing...';
        verificationResultEl.textContent = ''; // Clear previous verification
        decryptionSection.style.display = 'block';

        try {
            const response = await fetch('/api/decrypt', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(currentEncryptionResult),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || `HTTP error! status: ${response.status}`);
            }

            const decryptedHashValue = data.decrypted_hash;
            decryptedHashEl.textContent = decryptedHashValue;

            // Display decryption steps
            displayDecryptionSteps(
                currentEncryptionResult.iv,
                currentEncryptionResult.encrypted_data,
                currentEncryptionResult.key,
                decryptedHashValue,      // Pass the actual decrypted hash
                currentHashedPassword   // Pass the original hash for verification display
            );

            // Verification UI update
            if (decryptedHashValue === currentHashedPassword) {
                verificationResultEl.textContent = '✓ SUCCESS: Decrypted hash matches the original hash.';
                verificationResultEl.style.color = '#2ecc71'; // Green
            } else {
                verificationResultEl.textContent = '✗ ERROR: Decrypted hash does NOT match the original hash.';
                verificationResultEl.style.color = '#e74c3c'; // Red
            }
             displaySuccess('Decryption complete.');

        } catch (error) {
            console.error('Error decrypting hash:', error);
            displayError(`Decryption failed: ${error.message}`);
            // Update steps to show failure
            displayDecryptionSteps(
                currentEncryptionResult?.iv || 'N/A', 
                currentEncryptionResult?.encrypted_data || 'N/A', 
                currentEncryptionResult?.key || 'N/A', 
                'Decryption Failed', 
                currentHashedPassword || 'N/A'
            );
            verificationResultEl.textContent = '✗ ERROR: Decryption process failed.';
            verificationResultEl.style.color = '#e74c3c';
        } finally {
            // Keep decrypt button disabled after attempting decryption
            decryptButton.textContent = 'Decrypt Hash';
            decryptProgressBar.style.display = 'none'; // Hide decrypt progress bar
            // Optionally re-enable if you want users to retry?
            // decryptButton.disabled = false;
        }
    });

    togglePasswordButton.addEventListener('click', () => {
        const isPassword = passwordInput.type === 'password';
        passwordInput.type = isPassword ? 'text' : 'password';
        togglePasswordButton.textContent = isPassword ? 'Hide' : 'Show';
    });

    // Initial strength check if password field has value on load (e.g., browser autofill)
    if (passwordInput.value) {
        passwordInput.dispatchEvent(new Event('input'));
    }
}); 