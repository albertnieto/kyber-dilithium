import streamlit as st
import importlib

st.set_page_config(page_title="Digital Signature Standards", page_icon="✍️")

def main():
    st.title("✍️ Digital Signature Standards")
    st.write("This page demonstrates Digital Signature algorithms.")

    crypto_type = st.selectbox(
        "Select Cryptography Type",
        ["Pre-Quantum", "Post-Quantum"]
    )

    if crypto_type == "Pre-Quantum":
        algorithm_choice = st.selectbox(
            "Select Digital Signature Algorithm",
            ["SHA-256 Hashing", "Ed25519"]
        )
    else:
        pq_algorithms = [
            "dilithium2",
            "dilithium3",
            "dilithium4",
            "falcon_512",
            "falcon_1024",
            "rainbowIa_classic",
            "rainbowIa_cyclic",
            "rainbowIa_cyclic_compressed",
            "rainbowIIIc_classic",
            "rainbowIIIc_cyclic",
            "rainbowIIIc_cyclic_compressed",
            "rainbowVc_classic",
            "rainbowVc_cyclic",
            "rainbowVc_cyclic_compressed",
            "sphincs_haraka_128f_robust",
            "sphincs_haraka_128f_simple",
            "sphincs_haraka_128s_robust",
            "sphincs_haraka_128s_simple",
            "sphincs_haraka_192f_robust",
            "sphincs_haraka_192f_simple",
            "sphincs_haraka_192s_robust",
            "sphincs_haraka_192s_simple",
            "sphincs_haraka_256f_robust",
            "sphincs_haraka_256f_simple",
            "sphincs_haraka_256s_robust",
            "sphincs_haraka_256s_simple",
            "sphincs_sha256_128f_robust",
            "sphincs_sha256_128f_simple",
            "sphincs_sha256_128s_robust",
            "sphincs_sha256_128s_simple",
            "sphincs_sha256_192f_robust",
            "sphincs_sha256_192f_simple",
            "sphincs_sha256_192s_robust",
            "sphincs_sha256_192s_simple",
            "sphincs_sha256_256f_robust",
            "sphincs_sha256_256f_simple",
            "sphincs_sha256_256s_robust",
            "sphincs_sha256_256s_simple",
            "sphincs_shake256_128f_robust",
            "sphincs_shake256_128f_simple",
            "sphincs_shake256_128s_robust",
            "sphincs_shake256_128s_simple",
            "sphincs_shake256_192f_robust",
            "sphincs_shake256_192f_simple",
            "sphincs_shake256_192s_robust",
            "sphincs_shake256_192s_simple",
            "sphincs_shake256_256f_robust",
            "sphincs_shake256_256f_simple",
            "sphincs_shake256_256s_robust",
            "sphincs_shake256_256s_simple"
        ]

        algorithm_choice = st.selectbox(
            "Select Post-Quantum Digital Signature Algorithm",
            pq_algorithms
        )

    message = st.text_area("Enter a message to sign:", height=150)

    if st.button("Sign Message"):
        if message.strip():
            if crypto_type == "Pre-Quantum":
                if algorithm_choice == "SHA-256 Hashing":
                    from algorithms.DSA import SHA256
                    signature = SHA256.demo_signature_algorithm(message)
                    st.success("Signature (SHA-256 Hash):")
                    st.code(signature)
                elif algorithm_choice == "Ed25519":
                    from algorithms.DSA import Ed25519
                    signature_hex, verify_key_hex = Ed25519.ed25519_sign(message)
                    st.success("Message signed using Ed25519.")
                    st.write("**Signature (hex):**")
                    st.code(signature_hex)
                    st.write("**Verify Key (hex):**")
                    st.code(verify_key_hex)
                    if st.button("Verify Ed25519 Signature"):
                        is_valid = Ed25519.ed25519_verify(
                            message, signature_hex, verify_key_hex
                        )
                        if is_valid:
                            st.success("Signature is valid.")
                        else:
                            st.error("Signature is invalid.")
            else:
                try:
                    pq_module = importlib.import_module(f'pqcrypto.sign.{algorithm_choice}')
                    public_key, secret_key = pq_module.generate_keypair()
                    signature = pq_module.sign(secret_key, message.encode('utf-8'))

                    st.success(f"Message signed using {algorithm_choice}.")
                    st.write("**Signature (hex):**")
                    st.code(signature.hex())
                    st.write("**Public Key (hex):**")
                    st.code(public_key.hex())

                    if st.button(f"Verify {algorithm_choice} Signature"):
                        valid = pq_module.verify(public_key, message.encode('utf-8'), signature)
                        if valid:
                            st.success("Signature is valid.")
                        else:
                            st.error("Signature is invalid.")
                except Exception as e:
                    st.error(f"Error: {e}")
        else:
            st.error("Please enter a message to sign.")

if __name__ == "__main__":
    main()
