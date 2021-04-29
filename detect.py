import joblib
from flask import Flask, render_template, request
import features_new

app = Flask(__name__)

phish_model = open('new_model.pkl', 'rb')
clf = joblib.load(phish_model)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/getURL',methods=['GET','POST'])
def getURL():
    if request.method == 'POST':
        url = request.form['url']
        print(url)
        data = features_new.main(url)
        print(data)

        if data == "Invalid URL":
            value = "Invalid"
            return render_template("index.html", error=value)
        else:
            predicted_value = clf.predict(data)

            if int(predicted_value[0]) == 1:
                value = "Phishing"
                return render_template("index.html", error=value)
            elif int(predicted_value[0]) == -1:
                value = "Legitimate"
                return render_template("index.html", error=value)
            else:
                value = "Invalid Input"
                return render_template("index.html", error=value)

if __name__ == "__main__":
    app.run(debug=True)

