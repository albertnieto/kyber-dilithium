import streamlit as st
from secrets import compare_digest
from algorithms.KEM import B64
from pqcrypto.kem import (
    mceliece8192128,
    kyber512,
    kyber768,
    kyber1024,
    ntruhps2048509,
    ntruhps2048677,
    ntruhps4096821,
    ntruhrss701,
    saber,
    firesaber,
    frodokem1344aes,
    frodokem1344shake,
    frodokem640aes,
    frodokem640shake,
    frodokem976aes,
    frodokem976shake,
    lightsaber,
    mceliece348864,
    mceliece348864f,
    mceliece460896,
    mceliece460896f,
    mceliece6688128,
    mceliece6688128f,
    mceliece6960119,
    mceliece6960119f,
    mceliece8192128f,
)

st.set_page_config(page_title="Key Encapsulation Mechanisms", page_icon="🔑")

def main():
    st.title("🔑 Key Encapsulation Mechanisms")
    st.write("This page demonstrates Key Encapsulation Mechanisms (KEM).")

    crypto_type = st.selectbox(
        "Select Cryptography Type",
        ["Pre-Quantum", "Post-Quantum"]
    )

    if crypto_type == "Pre-Quantum":
        algorithm_choice = st.selectbox(
            "Select KEM Algorithm",
            ["Base64 Symmetric Key", "Fernet Symmetric Key"]
        )
    else:
        # List of Post-Quantum KEM Algorithms
        pq_algorithms = [
            "mceliece8192128",
            "kyber512",
            "kyber768",
            "kyber1024",
            "ntruhps2048509",
            "ntruhps2048677",
            "ntruhps4096821",
            "ntruhrss701",
            "saber",
            "firesaber",
            "frodokem1344aes",
            "frodokem1344shake",
            "frodokem640aes",
            "frodokem640shake",
            "frodokem976aes",
            "frodokem976shake",
            "lightsaber",
            "mceliece348864",
            "mceliece348864f",
            "mceliece460896",
            "mceliece460896f",
            "mceliece6688128",
            "mceliece6688128f",
            "mceliece6960119",
            "mceliece6960119f",
            "mceliece8192128f",
            # Add other algorithms as needed
        ]

        algorithm_choice = st.selectbox(
            "Select Post-Quantum KEM Algorithm",
            pq_algorithms
        )

    if st.button("Generate Key"):
        if crypto_type == "Pre-Quantum":
            if algorithm_choice == "Base64 Symmetric Key":
                key = B64.demo_kem_algorithm()
                st.success("Generated Key:")
                st.code(key)
            elif algorithm_choice == "Fernet Symmetric Key":
                key = FernetKEM.fernet_kem()
                st.success("Generated Fernet Key:")
                st.code(key)
        else:
            try:
                # Import the selected algorithm directly
                pq_module = getattr(locals()[algorithm_choice], algorithm_choice)
                public_key, secret_key = pq_module.generate_keypair()
                ciphertext, shared_secret_enc = pq_module.encrypt(public_key)
                shared_secret_dec = pq_module.decrypt(secret_key, ciphertext)

                st.success(f"Performed KEM using {algorithm_choice}.")
                st.write("**Public Key (hex):**")
                st.code(public_key.hex())
                st.write("**Ciphertext (hex):**")
                st.code(ciphertext.hex())
                st.write("**Shared Secret (Encapsulated):**")
                st.code(shared_secret_enc.hex())
                st.write("**Shared Secret (Decapsulated):**")
                st.code(shared_secret_dec.hex())

                if compare_digest(shared_secret_enc, shared_secret_dec):
                    st.success("Shared secrets match!")
                else:
                    st.error("Shared secrets do not match.")
            except AttributeError:
                st.error(f"Algorithm {algorithm_choice} not found in pqcrypto.kem.")
            except Exception as e:
                st.error(f"Error: {e}")

if __name__ == "__main__":
    main()
