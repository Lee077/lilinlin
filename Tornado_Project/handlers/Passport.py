# coding:utf-8

import hashlib
import config
import logging

from tornado.web import RequestHandler
from utils.session import Session
from handlers.BaseHandler import BaseHandler
from utils.response_code import RET

class RegisterHandler(BaseHandler):
	"""注册"""
	def post(self):
		print 1111
		#  def prepare(self):
			# request.headers  获取请求头
			# if self.request.headers.get("Content-Type", "").startswith("application/json"):
			#     self.json_args = json.loads(self.request.body)
			# else:
			#     self.json_args = None


			# json.dumps(字典)    ----> 字符串       写法是字典格式
			# json.loads(字典字符串)   --->  字典    写法是字典格式


#json四个方法： dump和dumps（从Python生成JSON），load和loads（解析JSON成Python的数据类型）
# dump和dumps的唯一区别是dump会生成一个类文件对象，dumps会生成字符串
# load和loads分别解析类文件对象和字符串格式的JSON
		mobile = self.json_args.get("mobile") 
		sms_code = self.json_args.get("phoneCode")
		password = self.json_args.get("passwd") 
		print mobile
		print sms_code
		print password
		# if not all([mobile, sms_code, password]):
		#     return self.write({"errno":RET.PARAMERR, "errmsg":"参数错误"})

		# real_code = self.redis.get("sms_code_%s" % mobile)

		# if real_code != str(sms_code) and str(sms_code) != "2468":
		#     return self.write({"errno":RET.DATAERR, "errmsg":"验证码无效！"})
		# # 密码加密
		# password = hashlib.sha256(config.passwd_hash_key + password).hexdigest()
		
		# try:
		res = self.db.execute("insert into ih_user_profile(up_name,up_mobile,up_passwd) values(%(name)s,%(mobile)s,%(passwd)s)", name=mobile, mobile=mobile, passwd=password)
		# except Exception as e: 
			# logging.error(e)
			# return self.write({"errno":RET.DATAEXIST, "errmsg":"手机号已注册！"})
		
		# try:
		self.session = Session(self)
		self.session.data['user_id'] = res
		self.session.data['name'] = mobile
		self.session.data['mobile'] = mobile
		self.session.save()
		# except Exception as e:
			# logging.error(e)
		self.write({"errno":RET.OK, "errmsg":"OK"})

class LoginHandler(BaseHandler):
	"""登录"""
	def post(self):
		mobile = self.json_args.get("mobile") 
		password = self.json_args.get("password")

		# if not all([mobile, password]):
		# 	return self.write({"errno":RET.PARAMERR, "errmsg":"参数错误"})
		# get 返回字典，单个     query返回字典，多个
		res = self.db.get("select up_user_id,up_name,up_passwd from ih_user_profile where up_mobile=%(mobile)s", mobile=mobile)
		# password = hashlib.sha256(config.passwd_hash_key + password).hexdigest()
		# 数据库里查到的数据是unicode
		if res and res["up_passwd"] == unicode(password):
			# try:
			self.session = Session(self)
			self.session.data['user_id'] = res['up_user_id']
			self.session.data['name'] = res['up_name']
			self.session.data['mobile'] = mobile
			self.session.save()
			# except Exception as e:
				# logging.error(e)
			# return self.write({"errno":RET.OK, "errmsg":"OK"})
			return self.write({"errno":0, "errmsg":"OK"})

		else:
			return self.write({"errno":RET.DATAERR, "errmsg":"手机号eeeee或密码错误！"})


class CheckLoginHandler(BaseHandler):
	"""检查登陆状态"""
	def get(self):
		# 在basehandler.py中
		# def get_current_user(self):
        #	self.session = Session(self)
        # 	return self.session.data

		if self.get_current_user():
			return self.write({"errno":RET.OK, 
				"errmsg":"true", 
				"data":{"name":self.session.data.get("name")}})
		else:
			self.write({"errno":RET.SESSIONERR, 
				"errmsg":"false"})