import streamlit as st
from algorithms.DSA import SHA256

st.set_page_config(page_title="Digital Signature Standards", page_icon="✍️")

def main():
    st.title("✍️ Digital Signature Standards")

    st.write("This page demonstrates Digital Signature algorithms.")

    message = st.text_area("Enter a message to sign:", value="", height=150)

    if st.button("Sign Message"):
        if message.strip():
            signature = SHA256.demo_signature_algorithm(message)
            st.success(f"Signature:\n\n{signature}")
        else:
            st.error("Please enter a message to sign.")

if __name__ == "__main__":
    main()
