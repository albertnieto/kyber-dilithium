import streamlit as st
from algorithms.DSA import SHA256, SPHINCSPlus

st.set_page_config(page_title="Digital Signature Standards", page_icon="✍️")

def main():
    st.title("✍️ Digital Signature Standards")
    st.write("This page demonstrates Digital Signature algorithms.")

    # Picklist to select the algorithm
    algorithm_choice = st.selectbox(
        "Select Digital Signature Algorithm",
        ["SHA-256 Hashing", "SPHINCS+"]
    )

    message = st.text_area("Enter a message to sign:", height=150)

    if st.button("Sign Message"):
        if message.strip():
            if algorithm_choice == "SHA-256 Hashing":
                signature = SHA256.demo_signature_algorithm(message)
                st.success("Signature (SHA-256 Hash):")
                st.code(signature)
            elif algorithm_choice == "SPHINCS+":
                with st.spinner("Generating SPHINCS+ signature..."):
                    signature_hex, public_key_hex = SPHINCSPlus.sphincs_plus_sign(message)
                st.success("Message signed using SPHINCS+.")
                st.write("**Signature (hex):**")
                st.code(signature_hex)
                st.write("**Public Key (hex):**")
                st.code(public_key_hex)

                # Optionally, verify the signature
                if st.button("Verify Signature"):
                    with st.spinner("Verifying SPHINCS+ signature..."):
                        is_valid = SPHINCSPlus.sphincs_plus_verify(
                            message, signature_hex, public_key_hex
                        )
                    if is_valid:
                        st.success("Signature is valid.")
                    else:
                        st.error("Signature is invalid.")
        else:
            st.error("Please enter a message to sign.")

if __name__ == "__main__":
    main()