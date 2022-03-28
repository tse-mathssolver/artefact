# Maths Solver

## Installation Instructions

Commands should be executed in the root of the project!

 1. Create a virtual environment.
```cmd
   python -m venv venv
```

 2. Activate the virtual environment.
```cmd
   venv\Scripts\activate.bat
```

 3. Install dependencies.
```cmd
   pip install -r requirements.txt
```

 4. Create database structure.
```cmd
   python
   from app import db
   db.create_all()
   exit()
```

 4. Run.
```cmd
   flask run
```
