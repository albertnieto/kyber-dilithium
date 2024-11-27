import streamlit as st
from algorithms.KEM import B64

st.set_page_config(page_title="Key Encapsulation Mechanisms", page_icon="🔑")

def main():
    st.title("🔑 Key Encapsulation Mechanisms")
    st.write("This page demonstrates Key Encapsulation Mechanisms (KEM).")

    # Picklist to select the KEM algorithm
    algorithm_choice = st.selectbox(
        "Select KEM Algorithm",
        ["Base64 Symmetric Key", "Fernet Symmetric Key"]
    )

    if st.button("Generate Key"):
        if algorithm_choice == "Base64 Symmetric Key":
            key = B64.demo_kem_algorithm()
            st.success("Generated Key:")
            st.code(key)
        elif algorithm_choice == "Fernet Symmetric Key":
            key = FernetKEM.fernet_kem()
            st.success("Generated Fernet Key:")
            st.code(key)

if __name__ == "__main__":
    main()