import init
from init import app
import models
import views
from init import db

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
