from rest_framework.decorators import detail_route
from rest_framework.response import Response
from rest_framework import status 
from rest_framework import filters
import django_filters

from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client

from iplantauth.models import create_token

from api.v2.views.base import AuthOptionalViewSet
from api.v2.serializers.details import LoginSerializer
from api import permissions
from core.models import Login, Provider, Identity, IdentityMembership, Credential
from core.models import AtmosphereUser as User
from core.models import Group, Leadership

from service.driver import get_account_driver
import datetime
from threepio import logger

class LinkFilter(django_filters.FilterSet):
    image_id = django_filters.CharFilter('application__id')
    created_by = django_filters.CharFilter('application__created_by__username')

    class Meta:
        model = Login
        fields = ['image_id', 'created_by']

class LoginKeystoneViewSet(AuthOptionalViewSet):
    """
    API endpoint that connects to keystone via using user's credentials 
    """
    
    queryset = Login.objects.all()
    permission_classes= (permissions.ApiAuthIgnore,)
    serializer_class = LoginSerializer
    search_fields = ('created_by__username')
    filter_class = LinkFilter
    filter_backends = (filters.OrderingFilter, filters.DjangoFilterBackend)
    http_method_names=['get','post','head','options','trace']


    def create(self, request):
        username = str(request.data['Username'])
        password = str(request.data['Password'])
        auth_url = "https://engage1.massopencloud.org:5000/v3/"

        #start RBB
        #super(LoginKeystoneViewSet, self).create(request)
        #logger.info("identity uuid:")
        #logger.info(i.uuid)
        #response_json = {
        #     "username":username,
        #     "token":scoped_token,
        #     "user_id":user_id,
        #     "identity_uuid":i.uuid,
        #     "identity_id":i.id,
        #     "project_id":project_id,
        #     "project_list":project_list
        #     }
        #return Response(response_json,status=status.HTTP_201_CREATED)        
        #End RBB        

        # Assuming each person belongs to 

        unscoped_auth=v3.Password(username=username,password=password,auth_url=auth_url,user_domain_name="Default",unscoped=True)
        unscoped_sess=session.Session(auth=unscoped_auth)
        try: 
            unscoped_token=unscoped_sess.get_token()
            try:
                auth=v3.Token(auth_url=auth_url,token=unscoped_token)
                sess=session.Session(auth=auth)
                user_id=sess.get_user_id()
                scoped_token=sess.get_token()
                password=request.data.pop('Password')
                request.data['ScopedToken']=scoped_token
                request.data['UnscopedToken']=unscoped_token
                request.data['UserID']=user_id
                project_id = sess.get_project_id()       #this just gets the default project id
                request.data['project_id'] = project_id 
                try:
                    keystone = client.Client(session=sess)
                    projects = keystone.projects.list(user=user_id)
                    project_list = []
                    for project in projects:
                         project_list.append(str(project.name))
                    request.data['project_list'] = list(project_list)
                except:
                    return Response("Unable to get a project list",status=status.HTTP_403_FORBIDDEN)
            except:
                return Response("Unable to get a scoped token", status=status.HTTP_403_FORBIDDEN)
        except:
            return Response("Unable to get a unscoped token",status=status.HTTP_403_FORBIDDEN)              
        #TODO: change token to auth_token as this is what is in the page - keeping it token for now.
        #
        #maintain the (0 or 1) to 1 relationship between AtmosphereUser (User) and a Keystone User.
        # - note: Troposphere/Atmosphere has convoluded the AtmosphereUser with all of the cloud users
        #         This will change as they are working towards being a cloud aggragator.  We are not. 
        
        #This is how the create user script works.  As it calls keystone, the atmosphere user is the same as the
        #the openstack user.
        #
        #need to fill in the data model: user, identity, identity_membership, credential
        #  identity membership is what relates an identity to an allocation, group and a quota
        #       allocation_id=1 and quota_id=2 are the defaults  - 
        #       group_id=3 (group lead by user "lucas")
        #
        #create a user if one deosn't exist (or update it).
        try: 
            u = User.objects.get(username=username) #see if the account exists
        except:
            u=User()
        u.username=username
        u.domain = "Default"
        u.user_id = user_id        
        u.password="TrustNoOne"  #dummy value - not used for keystone
        u.save()

        #create a token - see if we can do it here!
        #logger.info("creating token")
      
        create_token(username,token_key=unscoped_token,token_expire=(datetime.datetime.utcnow()+datetime.timedelta(hours=1)))
       
        #every user needs a group of their own
        #Allocation occurs through groups - this isn't quite the open stack way, but it is the troposphere way.
        #Required to view providers (as well to use any of the "membership" tables
        try:
            g = Group.objects.get(name=username)
        except:
            g = Group(name=username)
            g.save()
        g.user_set.add(u)  #this adds to atmosphere_user_group table
        g.save()

        #and make them a leader of that group as that seems to confer the permissions to view images
        try:
            l = Leadership.objects.get(user=u, group=g) 
        except:
            l=Leadership(user_id=u.id, group_id=g.group_ptr_id)
            l.save()
 
        #u=User.objects.get(username=username)  #get this after we have created it as it has the atmosphere_user.id that we need
        #
        try:
            i = Identity.objects.get(created_by=u.id, provider=4)
        except:
            i = Identity()
        i.created_by_id=u.id
        i.provider_id=4
        i.save()
        #
        u.selected_identity_id=i.id
        u.save()
        #
        provider = Provider.objects.get(id=4)
        #The selected router/external network should only be on the provider side.
        selected_router=provider.select_router()
        Identity.update_credential( i, 'router_name', selected_router, replace=True)
        #
        try:
            im=IdentityMembership.objects.get(identity_id=i.id, member_id=g.group_ptr_id)
        except:
            im=IdentityMembership()
        im.allocation_id=1 #im treating this as a default TODO: should be looked into
        im.quota_id=2      #im treating this as a default TODO: should be looked into
        im.member_id=g.group_ptr_id  
        im.identity_id=i.id 
        im.save_local()
        
        # 
        try: 
            cred=Credential.objects.get(identity_id=i.id,key='key')
            if cred.value != username:
                cred.value = username
                cred.save()
        except:
             cred=Credential()
        cred.key='key'
        cred.value=username
        cred.identity_id=i.id
        cred.save()
        #       
        try:
            cred=Credential.objects.get(identity_id=i.id,key='ex_force_auth_token');
        except:
            cred=Credential()
        cred.key='ex_force_auth_token'
        cred.value=scoped_token
        cred.identity_id=i.id
        cred.save()
        #
        try:
            cred=Credential.objects.get(identity_id=i.id,key='ex_force_base_url');
        except:
            cred=Credential()
        cred.key='ex_force_base_url'
        #cred.value='https://engage1.massopencloud.org:5000/v2.0/tokens/';
        cred.value='https://engage1.massopencloud.org:8774/v2/' + str(project_id) + '/';
        cred.identity_id=i.id
        cred.save()
        #
        try:
            cred=Credential.objects.get(identity_id=i.id,key='ex_force_auth_url');
        except:
            cred=Credential()
        cred.key='ex_force_auth_url'
        #cred.value='https://engage1.massopencloud.org:5000/v2.0/tokens/';
        cred.value='https://engage1.massopencloud.org:5000';
        cred.identity_id=i.id
        cred.save()
        
        #TODO: pick the value up from the UI
        try:
            cred=Credential.objects.get(identity_id=i.id,key='ex_project_name');
        except:
            cred=Credential()
        cred.key='ex_project_name'
        cred.value=projects[0].name
        #cred.value='atmosphere'
        cred.identity_id=i.id
        cred.save()

        #
        try:
            cred=Credential.objects.get(identity_id=i.id,key='ex_tenant_name');
        except:
            cred=Credential()
        cred.key='ex_tenant_name'
        cred.value=projects[0].name
        #cred.value='atmosphere'
        cred.identity_id=i.id
        cred.save()

        #
        try:
            cred=Credential.objects.get(identity_id=i.id,key='ex_domain_name');
        except:
            cred=Credential()
        cred.key='ex_domain_name'
        cred.value='Default'
        cred.identity_id=i.id
        cred.save()

	#
        try:
            cred=Credential.objects.get(identity_id=i.id,key='ex_force_auth_version');
        except:
            cred=Credential()
        cred.key='ex_force_auth_version'
        cred.value='3.x_password'
        cred.identity_id=i.id
        cred.save()

	#
        try:
            cred=Credential.objects.get(identity_id=i.id,key='ex_force_service_region');
        except:
            cred=Credential()
        cred.key='ex_force_service_region'
        cred.value='MOC_Engage1'
        cred.identity_id=i.id
        cred.save()

	#
        try:
            cred=Credential.objects.get(identity_id=i.id,key='os_user_id');
        except:
            cred=Credential()
        cred.key='os_user_id'
        cred.value=user_id
        cred.identity_id=i.id
        cred.save()

	#
        try:
            cred=Credential.objects.get(identity_id=i.id,key='os_project_id');
        except:
            cred=Credential()
        cred.key='os_project_id'
        cred.value=projects[0].id
        cred.identity_id=i.id
        cred.save()

        #provider has to be done here after the identity is created to our provider
        #this way the acct_driver is created with the credetials that have been added to the
        #provider (MOC) AND the identity (in essence the mapping between users and their provider)
        all_creds=i.get_all_credentials() 
        acct_driver=get_account_driver(provider,raise_exception=False,**all_creds)
        if not acct_driver:
            account_provider=provider.accountprovider_set.first();
            logger.info("Could not create the account driver for provider: %s" % account_provider);
            return Response("Could not create the account driver",status=status.HTTP_403_FORBIDDEN)

        #request.user=u
        super(LoginKeystoneViewSet, self).create(request)
        logger.info("unscoped token:")
        logger.info(unscoped_token)
        logger.info("scoped token:")
        logger.info(scoped_token)
        response_json = {
            "username":username,
            "token":unscoped_token,
            "user_id":user_id,
            "identity_uuid":i.uuid,
            "identity_id":i.id,
            "project_id":project_id,
            "project_list":project_list
            }
        

        #need to refresh the esh_driver
  
        return Response(response_json,status=status.HTTP_201_CREATED)

    def get_serializer_class(self):
        return self.serializer_class
    
    #def get_permissions(self):
    #    return self.permission_classes

    #def get_queryset(self):
    #    request_user = str(self.request.data['Username'])
    #    return request_user    
