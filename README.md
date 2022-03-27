# Maths Solver

## Installation Instructions

Commands should be executed in the root of the project!

 1. Create a virtual environment.
 > python -m venv venv

 2. Activate the virtual environment.
 > venv\Scripts\activate.bat

 3. Install dependencies.
 > pip install -r requirements.txt

 4. Create database structure.
 > python
 > from app import db
 > db.create_all()
 > exit()

 4. Run.
 > flask run