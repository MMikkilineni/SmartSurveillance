from flask import Flask,request,jsonify,json
import requests
from boto3.dynamodb.conditions import Attr
import boto3
import boto.dynamodb
from functools import wraps
from flasgger import Swagger
from flask import jsonify
from flask import request, current_app
import decimal

app = Flask(__name__)
dynamodb = boto3.resource('dynamodb')
Swagger(app)



def jsonp(func):
    """Wraps JSONified output for JSONP requests."""
    @wraps(func)
    def decorated_function(*args, **kwargs):
        callback = request.args.get('callback', False)
        if callback:
            data = str(func(*args, **kwargs).data)
            content = str(callback) + '(' + data + ')'
            mimetype = 'application/javascript'
            return current_app.response_class(content, mimetype=mimetype)
        else:
            return func(*args, **kwargs)
    return decorated_function

@app.route('/login',methods=['POST'])
def verify_login():
    """
    This API is to authenticate users registered with Smart Sensor App
    ---
    tags:
        - User
    """
    user_table = dynamodb.Table('users')
    print request.authorization.username
    items = user_table.scan(FilterExpression=Attr('email').eq(request.authorization.username) and Attr('password').eq(request.authorization.password))
    if items['Count'] == 1:
        return jsonify(data={'Success':True,'Message':'Authenticated user'})
    else:
        return jsonify({'Success': False, 'Message': 'Invalid user'})


@app.route('/user/register', methods=['POST'])
def register_users():
    """
    This API is to register new users with Smart Sensor App
    ---
    tags:
        - User
    """
    try:
        request_item = json.loads(request.data)
        print request_item['email']
        table = dynamodb.Table('users')
        if not (check_user('users','email',request_item['email'])):
            table.put_item(Item=request_item)
            return jsonify({'Success':True,'Message':'User created successfully'})
        else:
            return jsonify({'Success': False, 'Message': 'User already exists'})
    except Exception as e:
        return jsonify({'Success': False, 'Message': e.message})


def check_user(tablename,primarykey,value):
    try:
        table = dynamodb.Table(tablename)
        items = table.scan(FilterExpression=Attr(primarykey).eq(value))
        print items['Count']
        if items['Count'] == 1:
            return True
        else:
            return False
    except Exception as e:
        return False

@app.route('/sensor/register', methods=['GET'])
@jsonp
def register_sensors():
    """
    This API is used to register the sensors to sensorpool by the Sensor provider
    ---
    tags:
    - Sensorpool
    """
    try:
        request_item = {
            'sensorid': request.args.get('sensorid'),
            'sensorname': request.args.get('sensorname'),
            'manufacturer': request.args.get('manufactuter'),
            'sensortype': request.args.get('sensortype'),
            'provisionedto': request.args.get('proviionedto'),
            'sensorstatus': request.args.get('sensorstatus'),
        }
        print request_item['sensorid']
        table = dynamodb.Table('sensorpool')
        if not (check_user('sensorpool','sensorid',request_item['sensorid'])):
            table.put_item(Item=request_item)
            return jsonify({'Success':True,'Message':'Sensor created successfully'})
        else:
            return jsonify({'Success': False, 'Message': 'Sensor already exists'})
    except Exception as e:
        return jsonify({'Success': False, 'Message': e.message})


@app.route('/sensorpool/list',methods=['GET'])
@jsonp
def get_available_sensorpool():
    """
    This API is used to get all the availabe sensors from sensorpool
    ---
    tags:
    - Sensorpool
    """
    try:
        table = dynamodb.Table('sensorpool')
        items = table.scan(FilterExpression=Attr('sensorstatus').eq('Available'))
        return jsonify({'Success':True,'Message':'Request is successful','Response':items,'Count': items['Count']})
    except Exception as e:
        return jsonify({'Success': False, 'Message': e.message})

@app.route('/sensorpool/listsensor', methods=['GET'])
@jsonp
def get_sensorpool():
    """
    This API is used to get all the availabe sensors from sensorpool
    ---
    tags:
    - Sensorpool
    """
    try:
        table = dynamodb.Table('sensorpool')
        items = table.scan()
        return jsonify({'Success': True, 'Message': 'Request is successful', 'Response': items, 'Count': items['Count']})
    except Exception as e:
        return jsonify({'Success': False, 'Message': e.message})


#@app.route('/sensor/<string:sensorID>',methods=['GET'])
#def get_sensor_information(sensorID):
#    """
#    This API is used to get the sensor information using sensor id from Sensorpool
#    ---
#    tags:
#    - Sensorpool
#    """
#    try:
#        table = dynamodb.Table('sensorpool')
#        items = table.scan(FilterExpression=Attr('sensorid').eq(sensorID))
#        return jsonify({'Success':True,'Message':'Request is successful','Response':items,'Count': items['Count']})
#    except Exception as e:
#        return jsonify({'Success': False, 'Message': e.message})


@app.route('/sensor/status/<string:sensorid>/<string:status>', methods=['PUT'])
def update_sensor_status(sensorid,status):
    """
    This API is used to Update the sensor status using sensor id in Sensorpool
    ---
    tags:
    - Sensorpool
    """
    table = dynamodb.Table('sensorpool')
    try:
        table.update_item(
            Key={
                'sensorid': sensorid
            },
            UpdateExpression="set sensorstatus = :status",
            ConditionExpression="sensorid = :id",
            ExpressionAttributeValues={
                ':id': sensorid,
                ':status': status
            },
            ReturnValues="UPDATED_NEW"
        )
        return jsonify({'Success':True,'Message':'Record updated successfully'})
    except Exception as e:
        return jsonify({'Success': False, 'Message': e.message})


@app.route('/sensor/add', methods=['GET'])
@jsonp
def create_sensors():
    """
    This API is used to create/register new sensor with VTA
    ---
    tags:
    - Sensor
    """
    try:
        request_item = {
            'sensorid': request.args.get('sensorid'),
            'sensorname': request.args.get('sensorname'),
            'sensorgroup': request.args.get('sensorgroup'),
            'sensorhub': request.args.get('sensorhub'),
            'sensorstatus': request.args.get('sensorstatus'),
        }
        print request_item['sensorid']
        table = dynamodb.Table('sensor')
        if not (check_user('sensor','sensorid',request_item['sensorid'])):
            table.put_item(Item=request_item)
            pool_table = dynamodb.Table('sensorpool')
            response = pool_table.update_item(
                Key={
                    'sensorid': request_item['sensorid']
                },
                UpdateExpression="set sensorstatus = :status",
                ConditionExpression="sensorid = :id",
                ExpressionAttributeValues={
                    ':id': request_item['sensorid'],
                    ':status': 'Provisioned'
                },
                ReturnValues="UPDATED_NEW"
            )
            return jsonify({'Success':True,'Message':'Sensor created successfully'})
        else:
            return jsonify({'Success': False, 'Message': 'Sensor already procured by you'})
    except Exception as e:
        return jsonify({'Success': False, 'Message': e.message})


@app.route('/sensor/activate',methods=['GET'])
@jsonp
def activate_sensors():
    """
    This API is used to Activate the sensor with VTA and invoke lambda to publish sensor data
    ---
    tags:
    - Sensor
    """
    try:
        sensorid = request.args.get('sensorid')
        table = dynamodb.Table('sensor')
        try:
            table.update_item(
                Key={
                    'sensorid': sensorid
                },
                UpdateExpression="set sensorstatus = :status",
                ConditionExpression="sensorid = :id",
                ExpressionAttributeValues={
                    ':id': sensorid,
                    ':status': 'Active'
                },
                ReturnValues="UPDATED_NEW"
            )
            url = 'https://cs5ti98u99.execute-api.us-west-2.amazonaws.com/prod/sensors'
            payload = {'sensorId': int(sensorid), 'op': 'start'}
            headers = {'content-type': 'application/json'}
            r = requests.post(url, data=json.dumps(payload), headers=headers)
            return r.text
            return jsonify({'Success': True, 'Message': 'Sensor activated successfully'})
        except Exception as e:
            return jsonify({'Success': False, 'Message': e.message})
    except Exception as e:
        return jsonify({'Success': False, 'Message': e.message})


@app.route('/sensor/deactivate',methods=['GET'])
@jsonp
def deactivate_sensors():
    """
    This API is used to deactivate sensor with VTA and invoke lambda to stop publishing sensor data
    ---
    tags:
    - Sensor
    """
    try:
        sensorid = request.args.get('sensorid')
        table = dynamodb.Table('sensor')
        try:
            response = table.update_item(
                Key={
                    'sensorid': sensorid
                },
                UpdateExpression="set sensorstatus = :status",
                ConditionExpression="sensorid = :id",
                ExpressionAttributeValues={
                    ':id': sensorid,
                    ':status': 'Inactive'
                },
                ReturnValues="UPDATED_NEW"
            )
            url = 'https://cs5ti98u99.execute-api.us-west-2.amazonaws.com/prod/sensors'
            payload = {'sensorId': int(sensorid), 'op': 'stop'}
            headers = {'content-type': 'application/json'}
            r = requests.post(url, data=json.dumps(payload), headers=headers)
            return r.text
            return jsonify({'Success': True, 'Message': 'Sensor deactivated successfully'})
        except Exception as e:
            return jsonify({'Success': False, 'Message': e.message})
    except Exception as e:
        return jsonify({'Success': False, 'Message': e.message})

@app.route('/sensor/list',methods=['GET'])
@jsonp
def get_sensor_list():
    """
    This API is used to get list of all sensor data those are Active with VTA
    ---
    tags:
    - Sensor
    """
    try:
        table = dynamodb.Table('sensor')
        items = table.scan()
        return jsonify({'Success':True,'Message':'Request is successful','Response':items['Items'],'Count': items['Count']})
    except Exception as e:
        return jsonify({'Success': False, 'Message': e.message})


@app.route('/sensordata/list',methods=['GET'])
@jsonp
def get_sensor_data():
    """
    This API is used to get list of all sensor data those are Active with VTA
    ---
    tags:
    - Sensor
    """
    try:
        table = dynamodb.Table('sensorData1')
        items = table.scan()
        return jsonify({'Success':True,'Message':'Request is successful','Response':items['Items'],'Count': items['Count']})
    except Exception as e:
        return jsonify({'Success': False, 'Message': e.message})

@app.route('/sensorgroups/list',methods=['GET'])
@jsonp
def get_sensorgroups():
    """
    This API is used to get list of all sensor groups with VTA
    ---
    tags:
    - Sensor
    """
    try:
        table = dynamodb.Table('sensorGroups')
        items = table.scan()
        return jsonify({'Success':True,'Message':'Request is successful','Response':items['Items'],'Count': items['Count']})
    except Exception as e:
        return jsonify({'Success': False, 'Message': e.message})

@app.route('/sensor/suspend', methods=['GET'])
@jsonp
def delete_sensors():
    """
    This API is used to suspend sensor with VTA
    ---
    tags:
    - Sensor
    """
    try:
        sensorid = request.args.get('sensorid')
        print sensorid
        table = dynamodb.Table('sensor')
        if (check_user('sensor','sensorid',sensorid)):
            table.delete_item(
                Key={
                    'sensorid': sensorid
                },
                ConditionExpression="sensorid = :id",
                ExpressionAttributeValues={
                    ':id': sensorid,
                }
            )
            pool_table = dynamodb.Table('sensorpool')
            response = pool_table.update_item(
                Key={
                    'sensorid': sensorid
                },
                UpdateExpression="set sensorstatus = :status",
                ConditionExpression="sensorid = :id",
                ExpressionAttributeValues={
                    ':id': sensorid,
                    ':status': 'Available'
                },
                ReturnValues="UPDATED_NEW"
            )
            return response
            return jsonify({'Success':True,'Message':'Sensor suspended successfully'})
        else:
            return jsonify({'Success': False, 'Message': 'Sensor not suspended'})
    except Exception as e:
        return jsonify({'Success': False, 'Message': e.message})


if __name__ == '__main__':
    app.run(host= '0.0.0.0')