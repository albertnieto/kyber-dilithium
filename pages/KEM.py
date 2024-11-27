import streamlit as st
from algorithms.KEM import B64

st.set_page_config(page_title="Key Encapsulation Mechanisms", page_icon="🔑")

def main():
    st.title("🔑 Key Encapsulation Mechanisms")
    st.write("This page demonstrates Key Encapsulation Mechanisms (KEM).")

    cryptography_type = st.selectbox(
        "Select Cryptography Type",
        ["Pre-Quantum", "Post-Quantum"]
    )

    if cryptography_type == "Pre-Quantum":
        algorithm_options = ["Base64 Symmetric Key"]
    else:
        algorithm_options = []

    if cryptography_type == "Pre-Quantum":
        algorithm_choice = st.selectbox(
            "Select KEM Algorithm",
            algorithm_options
        )
    else:
        st.info("No post-quantum KEM algorithms available yet.")
        algorithm_choice = None

    if st.button("Generate Key"):
        if cryptography_type == "Pre-Quantum":
            if algorithm_choice == "Base64 Symmetric Key":
                key = B64.demo_kem_algorithm()
                st.success("Generated Key:")
                st.code(key)
        elif cryptography_type == "Post-Quantum":
            st.error("No post-quantum KEM algorithms available yet.")

if __name__ == "__main__":
    main()
