"""
  login model for atmosphere.
"""
import uuid

from django.db import models

from core.query import only_current


class Login(models.Model):

    # Required
    id = models.UUIDField(primary_key=True, default=uuid.uuid4,
                          unique=True, editable=False)
    Username = models.CharField(max_length=256)
    UnscopedToken = models.CharField(max_length=256,default='')
    ScopedToken = models.CharField(max_length=256,default='')
    ProjectNo = models.IntegerField(default=0)
    OpenStackDomain = models.CharField(max_length=256,default='')
    OpenStackUserID = models.CharField(max_length=256,default='')
    # User/Identity that created the external link
    #created_by = models.ForeignKey('AtmosphereUser')

    #def get_projects(self, user):
    #    projects = self.projects.filter(
    #        only_current(),
    #        owner=user,
    #    )
    #    return projects

    def __unicode__(self):
        return "-Author: %s" % (self.Username)

    class Meta:
        db_table = 'login'
        app_label = 'core'
