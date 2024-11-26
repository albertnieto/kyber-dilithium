# pages/key_encapsulation_mechanisms.py

import streamlit as st
from algorithms import key_encapsulation

st.set_page_config(page_title="Key Encapsulation Mechanisms", page_icon="🔑")

def main():
    st.title("🔑 Key Encapsulation Mechanisms")

    st.write("This page demonstrates Key Encapsulation Mechanisms (KEM).")

    if st.button("Generate Key"):
        key = key_encapsulation.demo_kem_algorithm()
        st.success(f"Generated Key:\n\n{key}")

if __name__ == "__main__":
    main()
