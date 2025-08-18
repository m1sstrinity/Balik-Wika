from flask import Blueprint, render_template

landing_bp = Blueprint(
    'landing',
    __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path='/landing_static'  # 👈 this changes the public URL
)


@landing_bp.route('/')
def home():
    return render_template('landingpage.html')

@landing_bp.route('/layunin')
def layunin():
    return render_template('layunin.html')

@landing_bp.route('/contactus')
def contactus():
    return render_template('contactus.html')
