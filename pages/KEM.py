import streamlit as st
import importlib
import pkgutil
import pqcrypto.kem

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
        # Dynamically list all available post-quantum KEM algorithms
        package = pqcrypto.kem
        pq_algorithms = [name for _, name, _ in pkgutil.iter_modules(package.__path__)]
        algorithm_choice = st.selectbox(
            "Select Post-Quantum KEM Algorithm",
            pq_algorithms
        )

    if st.button("Generate Key"):
        if crypto_type == "Pre-Quantum":
            if algorithm_choice == "Base64 Symmetric Key":
                from algorithms.KEM import B64
                key = B64.demo_kem_algorithm()
                st.success("Generated Key:")
                st.code(key)
            elif algorithm_choice == "Fernet Symmetric Key":
                from algorithms.KEM import FernetKEM
                key = FernetKEM.fernet_kem()
                st.success("Generated Fernet Key:")
                st.code(key)
        else:
            try:
                # Dynamically import the selected algorithm module
                pq_module = importlib.import_module(f'pqcrypto.kem.{algorithm_choice}')
                from secrets import compare_digest

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
            except Exception as e:
                st.error(f"Error: {e}")

if __name__ == "__main__":
    main()
