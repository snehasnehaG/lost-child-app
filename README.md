Project Title

Lost Child Search & Identification App

Project Description

The Lost Child Search & Identification App is a computer vision and machine learning-powered application designed to assist in locating and identifying missing children. By utilizing facial recognition and feature matching, the application allows users or law enforcement officials to upload images of found individuals to compare against a database of registered missing children, facilitating rapid identification and reunion.

Objectives

Rapid Identification: Reduce the time needed to match found or missing children with registered reports.

Automated Matching: Leverage facial recognition and feature extraction algorithms to automate candidate matching.

Secure Access Control: Provide secure user authentication and data management to protect sensitive personal records.

User-Friendly Portal: Offer an accessible interface for submitting search queries, reporting missing persons, and viewing match results.

Technologies Used

Programming Language: Python 3.8+

Framework / Web Interface: Streamlit (or Flask/FastAPI based on app.py)

Machine Learning & Computer Vision: OpenCV, face_recognition / Deep Learning libraries (PyTorch/TensorFlow)

Security & Authentication: passlib, streamlit-authenticator (assisted by make_hash.py and secrets.toml)

Data Processing: Pandas, NumPy

Dataset

Primary Source: Internal database of registered missing children profiles containing demographic information and facial embeddings/images.

Secondary / Public Data: Publicly available benchmarks for facial recognition testing (e.g., LFW, UTKFace) or custom user uploads.

Installation

Clone the repository:

git clone https://github.com/snehasnehaG/lost-child-app.git
cd lost-child-app-main


Create and activate a virtual environment (optional but recommended):

python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate


Install the required dependencies:

pip install -r requirements.txt


How to Run

Generate Password Hashes (If configuring new users):

python make_hash.py


Launch the Application:

streamlit run app.py

Results and Output

Match Confidence Scores: The application processes uploaded images and displays potential matches along with a similarity/confidence score percentage.

Profile Overview: Detailed profile comparison views showing matched attributes (age, location reported missing, contact details for authorities).

Alert Generation: Visual confirmation and dashboard logging when a high-probability match is identified.

Project Structure

lost-child-app-main/
│
├── .gitattributes          # Git configuration file
├── .gitignore              # Files and folders ignored by Git
├── AGENTS.md               # Information on autonomous agents/contributor rules
├── README.md               # Project documentation
├── app.py                  # Main application script (UI and backend logic)
├── make_hash.py            # Utility script for hashing passwords/secrets
├── requirements.txt        # List of required Python packages
└── secrets.toml.example    # Configuration template for application secrets


Author

Hack Nova/ SNEHA G , JANAVI M, GOWTHAMI GM

Contact:
