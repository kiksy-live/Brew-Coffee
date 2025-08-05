from flask import Flask, request, jsonify
from flask_cors import CORS
import gspread
from google.oauth2.service_account import Credentials
import os
import logging
import uuid
import base64
from io import BytesIO
from datetime import datetime
from dotenv import load_dotenv # type: ignore
import traceback
import qrcode
from PIL import Image

# Load environment variables
load_dotenv()

# Helper function to generate unique order ID
def generate_order_id():
    """Generate a unique order ID using timestamp and UUID"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    unique_id = str(uuid.uuid4())[:4].upper()
    return f"ORD-{unique_id}"

# Helper function to generate QR code
def generate_qr_code(order_id, total_amount):
    """Generate QR code for payment"""
    # Create payment data (you can customize this format)
    payment_data = f"Order ID: {order_id}\nAmount: ₹{total_amount}\nCoffee Shop Payment"

    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(payment_data)
    qr.make(fit=True)

    # Create QR code image
    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to base64 string
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    img_str = base64.b64encode(buffer.getvalue()).decode()

    return img_str

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configure CORS
cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
CORS(app, origins=cors_origins)

# Configure Flask
app.config['ENV'] = os.getenv('FLASK_ENV', 'development')
app.config['DEBUG'] = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'

# Google Sheets setup
try:
    scope = ["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]
    creds_file = os.getenv("GOOGLE_SHEETS_CREDS_FILE")
    if not creds_file or not os.path.exists(creds_file):
        logger.error(f"Google Sheets credentials file not found: {creds_file}")
        sheet = None
    else:
        creds = Credentials.from_service_account_file(creds_file, scopes=scope)
        client = gspread.authorize(creds)
        spreadsheet_url = os.getenv("SHEET_URL")
        if not spreadsheet_url:
            logger.error("SHEET_URL environment variable not set")
            sheet = None
        else:
            try:
                sheet = client.open_by_url(spreadsheet_url)
                logger.info("Google Sheets connection established successfully")
            except gspread.exceptions.SpreadsheetNotFound:
                logger.error(f"Spreadsheet not found at URL: {spreadsheet_url}")
                logger.error("Please check that the spreadsheet exists and is shared with the service account")
                sheet = None
            except gspread.exceptions.APIError as e:
                logger.error(f"Google Sheets API error: {str(e)}")
                sheet = None
except Exception as e:
    logger.error(f"Failed to initialize Google Sheets: {str(e)}")
    sheet = None

@app.route('/register', methods=['POST'])
def register():
    try:
        # Validate request
        if not request.is_json:
            logger.warning("Register request received without JSON content type")
            return jsonify({'success': False, 'message': 'Content-Type must be application/json'}), 400

        data = request.json
        if not data:
            logger.warning("Register request received with empty JSON")
            return jsonify({'success': False, 'message': 'Request body cannot be empty'}), 400

        # Extract and validate data
        name = data.get('name', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        phone = data.get('phone', '').strip()

        # Validation
        if not name:
            return jsonify({'success': False, 'message': 'Name is required'}), 400

        if not email:
            return jsonify({'success': False, 'message': 'Email is required'}), 400

        if not password or len(password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400

        if not phone:
            return jsonify({'success': False, 'message': 'Phone number is required'}), 400

        # Check if Google Sheets is available
        if sheet is None:
            logger.error("Google Sheets not available for registration")
            return jsonify({'success': False, 'message': 'Service temporarily unavailable'}), 503

        # Check if user already exists
        try:
            users_data = sheet.get_worksheet(0).get_all_records()  # Assuming users are in first sheet
            for user in users_data:
                if user.get('Email', '').lower() == email:
                    return jsonify({'success': False, 'message': 'Email already registered'}), 400
        except Exception as e:
            logger.warning(f"Could not check existing users: {str(e)}")

        # Register new user
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        user_row = [timestamp, name, email, password, phone, 'Active']

        # Get the first worksheet (users)
        users_sheet = sheet.get_worksheet(0)

        # Check if headers exist, if not add them
        try:
            existing_headers = users_sheet.row_values(1)
            if not existing_headers or len(existing_headers) == 0:
                # Sheet is empty, add headers
                headers = ['Registration Date', 'Name', 'Email', 'Password', 'Phone', 'Status']
                users_sheet.append_row(headers)
        except Exception as e:
            # If there's an error reading the first row, assume sheet is empty
            headers = ['Registration Date', 'Name', 'Email', 'Password', 'Phone', 'Status']
            users_sheet.append_row(headers)

        # Add the user data
        users_sheet.append_row(user_row)

        logger.info(f"User registered successfully: {email}")
        return jsonify({'success': True, 'message': 'Registration successful! Please login.'})

    except Exception as e:
        logger.error(f"Error during registration: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        # Validate request
        if not request.is_json:
            logger.warning("Login request received without JSON content type")
            return jsonify({'success': False, 'message': 'Content-Type must be application/json'}), 400

        data = request.json
        if not data:
            logger.warning("Login request received with empty JSON")
            return jsonify({'success': False, 'message': 'Request body cannot be empty'}), 400

        # Extract and validate data
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        # Validation
        if not email:
            return jsonify({'success': False, 'message': 'Email is required'}), 400

        if not password:
            return jsonify({'success': False, 'message': 'Password is required'}), 400

        # Check if Google Sheets is available
        if sheet is None:
            logger.error("Google Sheets not available for login")
            return jsonify({'success': False, 'message': 'Service temporarily unavailable'}), 503

        # Check user credentials
        try:
            users_data = sheet.get_worksheet(0).get_all_records()
            logger.info(f"Login attempt for email: {email}")

            for user in users_data:
                stored_email = user.get('Email', '').strip().lower()
                if stored_email == email:
                    stored_password = str(user.get('Password', '')).strip()
                    input_password = str(password).strip()

                    logger.info(f"Found user: {stored_email}")
                    logger.info(f"Stored password length: {len(stored_password)}")
                    logger.info(f"Input password length: {len(input_password)}")

                    if stored_password == input_password:
                        # Login successful
                        user_info = {
                            'name': user.get('Name', ''),
                            'email': user.get('Email', ''),
                            'phone': user.get('Phone', '')
                        }
                        logger.info(f"User logged in successfully: {email}")
                        return jsonify({'success': True, 'message': 'Login successful!', 'user': user_info})
                    else:
                        logger.warning(f"Password mismatch for {email}")
                        logger.warning(f"Expected: '{stored_password}' (len: {len(stored_password)})")
                        logger.warning(f"Received: '{input_password}' (len: {len(input_password)})")
                        return jsonify({'success': False, 'message': 'Password is incorrect'}), 401

            # User not found
            logger.warning(f"User not found: {email}")
            return jsonify({'success': False, 'message': 'Email not found. Please register first.'}), 404

        except Exception as e:
            logger.error(f"Error checking user credentials: {str(e)}")
            return jsonify({'success': False, 'message': 'Error validating credentials'}), 500

    except Exception as e:
        logger.error(f"Error during login: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/order', methods=['POST'])
def order():
    try:
        # Validate request
        if not request.is_json:
            logger.warning("Order request received without JSON content type")
            return jsonify({'success': False, 'message': 'Content-Type must be application/json'}), 400

        data = request.json
        if not data:
            logger.warning("Order request received with empty JSON")
            return jsonify({'success': False, 'message': 'Request body cannot be empty'}), 400

        # Extract and validate data
        user = data.get('user', {})
        cart = data.get('cart', [])
        address = data.get('deliveryAddress', '')
        total = data.get('total', 0)

        # Validation
        if not user.get('email'):
            return jsonify({'success': False, 'message': 'User email is required'}), 400

        if not cart or len(cart) == 0:
            return jsonify({'success': False, 'message': 'Cart cannot be empty'}), 400

        if not address.strip():
            return jsonify({'success': False, 'message': 'Delivery address is required'}), 400

        if total <= 0:
            return jsonify({'success': False, 'message': 'Invalid total amount'}), 400

        # Check if Google Sheets is available
        if sheet is None:
            logger.error("Google Sheets not available for order processing")
            return jsonify({'success': False, 'message': 'Service temporarily unavailable'}), 503

        # Process order - save to second sheet (orders)
        items = ', '.join([f'{item.get("quantity", 1)}x {item.get("name", "")}' for item in cart])
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Extract service type, table number, and payment method
        service_type = data.get('serviceType', 'takeaway')
        table_number = data.get('tableNumber', '')
        payment_method = data.get('paymentMethod', 'counter')

        # Generate unique order ID
        order_id = generate_order_id()

        order_row = [timestamp, order_id, user.get('email', ''), user.get('name', ''), address, items, total, 'Pending', service_type, table_number, payment_method]

        # Try to add to second sheet (orders)
        try:
            orders_sheet = sheet.get_worksheet(1)
            # Check if headers need to be updated
            headers = orders_sheet.row_values(1)
            if len(headers) < 11 or 'Order ID' not in headers:
                # Update headers to include Order ID and Payment Method
                new_headers = ['Order Date', 'Order ID', 'Email', 'Name', 'Address', 'Items', 'Total', 'Status', 'Service Type', 'Table Number', 'Payment Method']
                orders_sheet.clear()
                orders_sheet.append_row(new_headers)
        except:
            # Create second sheet for orders if it doesn't exist
            orders_sheet = sheet.add_worksheet(title="Orders", rows="1000", cols="12")
            headers = ['Order Date', 'Order ID', 'Email', 'Name', 'Address', 'Items', 'Total', 'Status', 'Service Type', 'Table Number', 'Payment Method']
            orders_sheet.append_row(headers)

        orders_sheet.append_row(order_row)

        logger.info(f"Order placed successfully for {user.get('email')} - Order ID: {order_id} - Total: ₹{total}")
        return jsonify({
            'success': True,
            'message': 'Order placed successfully!',
            'order_id': order_id,
            'payment_method': payment_method
        })

    except Exception as e:
        logger.error(f"Error processing order: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/generate-qr', methods=['POST'])
def generate_payment_qr():
    """Generate QR code for payment"""
    try:
        data = request.get_json()
        order_id = data.get('order_id')
        total_amount = data.get('total_amount')

        if not order_id or not total_amount:
            return jsonify({'success': False, 'message': 'Order ID and total amount are required'}), 400

        # Generate QR code
        qr_code_base64 = generate_qr_code(order_id, total_amount)

        return jsonify({
            'success': True,
            'qr_code': qr_code_base64,
            'order_id': order_id,
            'amount': total_amount
        })

    except Exception as e:
        logger.error(f"Error generating QR code: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to generate QR code'}), 500

@app.route('/debug/users', methods=['GET'])
def debug_users():
    try:
        if sheet is None:
            return jsonify({'error': 'Google Sheets not available'}), 503

        users_data = sheet.get_worksheet(0).get_all_records()
        # Remove passwords from debug output for security
        safe_users = []
        for user in users_data:
            safe_user = {
                'name': user.get('Name', ''),
                'email': user.get('Email', ''),
                'phone': user.get('Phone', ''),
                'status': user.get('Status', ''),
                'registration_date': user.get('Registration Date', ''),
                'password_length': len(str(user.get('Password', '')))
            }
            safe_users.append(safe_user)

        return jsonify({'users': safe_users, 'count': len(safe_users)})
    except Exception as e:
        logger.error(f"Debug users failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/test', methods=['GET', 'POST'])
def test_endpoint():
    logger.info(f"Test endpoint called with method: {request.method}")
    if request.method == 'POST':
        data = request.get_json()
        logger.info(f"POST data received: {data}")
        return jsonify({'success': True, 'message': 'POST endpoint working', 'received_data': data})
    else:
        return jsonify({'success': True, 'message': 'GET endpoint working', 'timestamp': datetime.now().isoformat()})

@app.route('/orders/history/<email>', methods=['GET'])
def get_order_history(email):
    try:
        if sheet is None:
            return jsonify({'error': 'Google Sheets not available'}), 503

        # Get orders from second sheet
        try:
            orders_sheet = sheet.get_worksheet(1)
            orders_data = orders_sheet.get_all_records()
        except:
            # No orders sheet exists yet
            return jsonify({'orders': [], 'count': 0})

        # Filter orders for this user
        user_orders = []
        for order in orders_data:
            if order.get('Email', '').lower() == email.lower():
                user_orders.append({
                    'id': len(user_orders) + 1,  # Simple ID based on order
                    'order_id': order.get('Order ID', ''),
                    'order_date': order.get('Order Date', ''),
                    'items': order.get('Items', ''),
                    'total': order.get('Total', 0),
                    'status': order.get('Status', 'Pending'),
                    'table_number': order.get('Table Number', ''),
                    'service_type': order.get('Service Type', ''),
                    'payment_method': order.get('Payment Method', 'counter')
                })

        # Sort by date (newest first)
        user_orders.sort(key=lambda x: x['order_date'], reverse=True)

        logger.info(f"Retrieved {len(user_orders)} orders for {email}")
        return jsonify({'orders': user_orders, 'count': len(user_orders)})

    except Exception as e:
        logger.error(f"Error retrieving order history: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/orders/status/<email>', methods=['GET'])
def get_active_orders(email):
    try:
        if sheet is None:
            return jsonify({'error': 'Google Sheets not available'}), 503

        # Get orders from second sheet
        try:
            orders_sheet = sheet.get_worksheet(1)
            orders_data = orders_sheet.get_all_records()
        except:
            return jsonify({'active_orders': [], 'count': 0})

        # Filter active orders for this user
        active_orders = []
        for order in orders_data:
            if (order.get('Email', '').lower() == email.lower() and
                order.get('Status', '').lower() in ['pending', 'preparing', 'ready']):

                active_orders.append({
                    'id': len(active_orders) + 1,
                    'order_id': order.get('Order ID', ''),
                    'order_date': order.get('Order Date', ''),
                    'items': order.get('Items', ''),
                    'total': order.get('Total', 0),
                    'status': order.get('Status', 'Pending'),
                    'table_number': order.get('Table Number', ''),
                    'service_type': order.get('Service Type', ''),
                    'payment_method': order.get('Payment Method', 'counter'),
                    'estimated_time': get_estimated_time(order.get('Status', 'Pending'))
                })

        # Sort by date (newest first)
        active_orders.sort(key=lambda x: x['order_date'], reverse=True)

        return jsonify({'active_orders': active_orders, 'count': len(active_orders)})

    except Exception as e:
        logger.error(f"Error retrieving active orders: {str(e)}")
        return jsonify({'error': str(e)}), 500

def get_estimated_time(status):
    """Get estimated time based on order status"""
    status_times = {
        'pending': '5-10 minutes',
        'preparing': '3-8 minutes',
        'ready': 'Ready for pickup!',
        'completed': 'Completed',
        'received': 'Order Received by Customer',
        'cancelled': 'Cancelled'
    }
    return status_times.get(status.lower(), '5-10 minutes')

@app.route('/orders/update-status', methods=['POST'])
def update_order_status():
    logger.info("Update order status endpoint called")
    try:
        data = request.get_json()
        logger.info(f"Received data: {data}")

        email = data.get('email', '').strip().lower()
        order_id = data.get('orderId')
        new_status = data.get('status', '').strip()

        logger.info(f"Processing order update: email={email}, orderId={order_id}, status={new_status}")

        if not email or not order_id or not new_status:
            logger.warning("Missing required fields")
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400

        if sheet is None:
            return jsonify({'success': False, 'message': 'Google Sheets not available'}), 503

        # Get orders from second sheet
        try:
            orders_sheet = sheet.get_worksheet(1)
            orders_data = orders_sheet.get_all_records()
        except:
            return jsonify({'success': False, 'message': 'Orders sheet not found'}), 404

        # Find and update the order
        updated = False
        for i, order in enumerate(orders_data):
            if (order.get('Email', '').lower() == email and
                str(i + 1) == str(order_id)):  # Using row index as order ID

                # Update the status in the sheet (Status is column 7, index 6)
                row_number = i + 2  # +2 because sheets are 1-indexed and we have headers
                orders_sheet.update_cell(row_number, 7, new_status)
                updated = True
                break

        if updated:
            logger.info(f"Order {order_id} status updated to {new_status} for {email}")
            return jsonify({'success': True, 'message': f'Order status updated to {new_status}'})
        else:
            return jsonify({'success': False, 'message': 'Order not found'}), 404

    except Exception as e:
        logger.error(f"Error updating order status: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    try:
        # Check Google Sheets connectivity
        sheets_status = 'connected' if sheet is not None else 'disconnected'

        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'services': {
                'google_sheets': sheets_status
            }
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

@app.errorhandler(404)
def not_found(_):
    return jsonify({'success': False, 'message': 'Endpoint not found'}), 404

@app.errorhandler(405)
def method_not_allowed(_):
    return jsonify({'success': False, 'message': 'Method not allowed'}), 405

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({'success': False, 'message': 'Internal server error'}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    host = os.getenv('HOST', '0.0.0.0')
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'

    logger.info(f"Starting BrewMaster API server on {host}:{port}")
    app.run(host=host, port=port, debug=debug)
