
import jarray
import inspect
import os
import subprocess
import time
import json
import sys
import string as stringModule

from javax.swing import JCheckBox
from javax.swing import JList
from javax.swing import JTextArea
from javax.swing import BoxLayout
from java.awt import GridLayout
from java.awt import BorderLayout
from javax.swing import BorderFactory
from javax.swing import JToolBar
from javax.swing import JPanel
from javax.swing import JFrame
from javax.swing import JScrollPane
from javax.swing import JComponent
from java.awt.event import KeyListener
from org.python.core.util import StringUtil
from Registry import Registry
from java.lang import Class
from java.lang import System
from java.sql import DriverManager, SQLException
from java.util.logging import Level
from java.io import File
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils
DATETIME_FIELDS = ["LastModifiedTime", "ExpirationTime", "StartTime",
                   "EndTime", "LastModifiedOnClient", "OriginalLastModifiedOnClient"]

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.


class WintenTimelineIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Windows 10 Analyzer"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Parses and analyzes information regarding Windows 10's Timeline feature"

    def getModuleVersionNumber(self):
        return "0.1"

    def getDefaultIngestJobSettings(self):
        return Process_timelineWithUISettings()

    def hasIngestJobSettingsPanel(self):
        return True

    # TODO: Update class names to ones that you create below
    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, Process_timelineWithUISettings):
            raise IllegalArgumentException(
                "Expected settings argument to be instanceof SampleIngestModuleSettings")
        self.settings = settings
        return Process_AmcacheWithUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return WintenTimelineIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.


class WintenTimelineIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(WintenTimelineIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__,
                          inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.art_list = []

    def create_temp_directory(self, dir):
        try:
            os.mkdir(self.temp_dir + dir)
        except:
            self.log(Level.INFO, "ERROR: " + dir + " directory already exists")

    def index_artifact(self, blackboard, artifact, artifact_type):
        try:
            # Index the artifact for keyword search
            blackboard.indexArtifact(artifact)
        except Blackboard.BlackboardException as e:
            self.log(Level.SEVERE, "Error indexing artifact " +
                     artifact.getDisplayName())
        # Fire an event to notify the UI and others that there is a new log artifact
        IngestServices.getInstance().fireModuleDataEvent(
            ModuleDataEvent(WintenTimelineIngestModuleFactory.moduleName,
                            artifact_type, None))

    def create_artifact_type(self, art_name, art_desc, skCase):
        try:
            skCase.addBlackboardArtifactType(art_name, "WTA: " + art_desc)
        except:
            self.log(Level.INFO, "ERROR creating artifact type: " + art_desc)
        art = skCase.getArtifactType(art_name)
        self.art_list.append(art)
        return art

    def create_attribute_type(self, att_name, type, att_desc, skCase):
        try:
            skCase.addArtifactAttributeType(att_name, type, att_desc)
        except:
            self.log(Level.INFO, "ERROR creating attribute type: " + att_desc)
        return skCase.getAttributeType(att_name)

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context
        self.generic_att = {}
        if self.local_settings.getRawFlag():                #testing 
            self.log(Level.INFO,' all flags working')       #testing 
        if self.local_settings.getRegistryFlag():           #testing 
            self.log(Level.INFO,' all flags working')       #testing 
        if self.local_settings.getAnomaliesFlag():          #testing 
            self.log(Level.INFO,' all flags working')       #testing 
        
        self.temp_dir = Case.getCurrentCase().getTempDirectory()
        self.create_temp_directory("\WTA")
        skCase = Case.getCurrentCase().getSleuthkitCase()
        self.generic_att = {}
        #create lists for each type of artefact
        self.raw_names_list = ['Id', 'AppId', 'PackageIdHash', 'AppActivityId', 'ActivityType', 'ActivityStatus', 'LastModifiedTime', 'ExpirationTime', 'Payload', 'Priority', 'IsLocalOnly', 'PlatformDeviceId', 'CreatedInCloud', 'StartTime', 'EndTime', 'LastModifiedOnClient', 'GroupAppActivityId', 'ClipboardPayload', 'EnterpriseId', 'OriginalPayload', 'OriginalLastModifiedOnClient', 'ETag']        
        self.proc_names_list = ['Id', 'AppId', 'ActivityStatus', 'LastModifiedTime', 'ExpirationTime', 'Payload', 'IsLocalOnly', 'PlatformDeviceId', 'CreatedInCloud', 'StartTime', 'EndTime', 'LastModifiedOnClient', 'ClipboardPayload', 'ETag']        
        self.etag_names_list = ['Id', 'ETag']
        self.payload_names_list = ['Id', 'OriginalPayload', 'Payload']
        self.etag_names_list = ['Id', 'ETag']
        self.payload_names_list = ['Id', 'OriginalPayload', 'Payload']
        self.update_timestamp_list = ['Date Saved On Metadata', 'Date on config file']
        #create atts for the entire extraction 
        for name in self.raw_names_list:
            self.generic_att[name] = self.create_attribute_type(name, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, name, skCase)
        # create Application and Platform columns for AppId properties
        self.json_app_att = self.create_attribute_type('Application', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 'Application', skCase)
        self.json_platform_att = self.create_attribute_type('Platform', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 'Platform', skCase)
        self.json_file_or_url_opened_att = self.create_attribute_type('File or URL Opened', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 'File or URL Opened', skCase)
        self.json_used_program_att = self.create_attribute_type('Used Program', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 'Used Program', skCase)
        self.json_timezone_att = self.create_attribute_type('Timezone', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 'Timezone', skCase)
        # create attribute types for update_timestamp
        self.date_on_db = self.create_attribute_type('Date Saved On Metadata', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 'Date Saved On Metadata', skCase)
        self.date_on_config_file = self.create_attribute_type('Date on config file', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 'Date on config file', skCase)
        #create main art
        self.proc_data_art = self.create_artifact_type("TSK_WTA_SmartLU_Proc", "Processed content from SmartLookup", skCase)
        #create raw art if applicable
        if self.local_settings.getRawFlag():
            self.raw_data_art = self.create_artifact_type("TSK_WTA_SmartLU_Raw", "Raw content from SmartLookup", skCase)
        if self.local_settings.getAnomaliesFlag():           
            self.etag_art = self.create_artifact_type("TSK_WTA_ANOMALIES", "SmartLookup anomalous content", skCase)       
            self.payload_art = self.create_artifact_type("TSK_WTA_P_ANOMALIES", "SmartLookup anomalous payload content", skCase)
            self.update_timestamp_art = self.create_artifact_type("TSK_WTA_T_ANOMALIES", "Metadata anomalous update timestamp", skCase)

        self.cfg_active_att = self.create_attribute_type('User Timeline Status', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 'User timeline status', skCase)
        self.cfg_userId_att = self.create_attribute_type('User Id', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 'User Id', skCase)
        self.cfg_up_to_cloud_att = self.create_attribute_type('Sync with cloud', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 'Sync with cloud', skCase)
        self.cfg_collect_att = self.create_attribute_type('Windows collect Activities', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 'Windows collect Activities', skCase)
        self.config_art = self.create_artifact_type("TSK_WTA_Config", "Data from config file", skCase)
        if self.local_settings.getRegistryFlag():
            self.device_name = self.create_attribute_type('Device name', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 'Device name', skCase)
            self.device_type = self.create_attribute_type('Device type', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 'Device type', skCase)
            self.device_model = self.create_attribute_type('Device model', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 'Device model', skCase)
            self.device_maker = self.create_attribute_type('Device maker', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 'Device maker', skCase)
        
   
    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html

    def process(self, dataSource, progressBar):
        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        skCase = Case.getCurrentCase().getSleuthkitCase()
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "ActivitiesCache.db")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        fileCount = 0
        self.colNames = []
        for file in files:
            wtaDbPath = os.path.join(self.temp_dir + "\WTA", str(file.getId()))
            ContentUtils.writeToFile(file, File(wtaDbPath))
            try:
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection(
                    "jdbc:sqlite:%s" % wtaDbPath)
            except Exception as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " +
                         file.getName() + " (" + str(e) + ")")
                continue
                
            try:
                full_path = (file.getParentPath() + file.getName()) 
                split = full_path.split('/')
                cdPath = '/'.join(split[:-3])
                cdpconfig = fileManager.findFiles(dataSource, 'CDPGlobalSettings.cdp' ,cdPath)
                if cdpconfig:
                    self.cdpconfigPath = os.path.join(self.temp_dir , str(cdpconfig[0].getId()))
                    ContentUtils.writeToFile(cdpconfig[0], File(self.cdpconfigPath))
                else:
                    self.cdpconfigPath = 0
                if self.local_settings.getRegistryFlag():
                    dsPath = '/'.join(split[:-6])
                    ntuser = fileManager.findFiles(dataSource, 'NTUSER.DAT' ,dsPath)[0]
                    self.ntuserPath = os.path.join(self.temp_dir , str(ntuser.getId()))
                    ContentUtils.writeToFile(ntuser, File(self.ntuserPath))
            except Exception as e:
                self.log(Level.INFO, str(e) )
            try: 
                self.regValues = {}
                # if set to do so, extract and place on artifact all raw info 
                if self.local_settings.getRawFlag():
                    stmt = dbConn.createStatement()
                    tableContent = stmt.executeQuery("select hex(Id) 'Id', AppId, PackageIdHash, AppActivityId, ActivityType, ActivityStatus, LastModifiedTime, ExpirationTime, Payload, Priority, IsLocalOnly, PlatformDeviceId, CreatedInCloud, StartTime, EndTime, LastModifiedOnClient, GroupAppActivityId, ClipboardPayload, EnterpriseId, OriginalPayload, OriginalLastModifiedOnClient, ETag from SmartLookup")                  
                    self.extractRawDataFromDB(tableContent, file, blackboard, skCase)
                stmt = dbConn.createStatement()
                tableContent = stmt.executeQuery("select hex(Id) 'Id', AppId, PackageIdHash, AppActivityId, ActivityType, ActivityStatus, LastModifiedTime, ExpirationTime, Payload, Priority, IsLocalOnly, PlatformDeviceId, CreatedInCloud, StartTime, EndTime, LastModifiedOnClient, ClipboardPayload, OriginalPayload, OriginalLastModifiedOnClient, ETag from SmartLookup")                                
                self.extractProcessedData(tableContent,file,blackboard,skCase)
                #if set to do so, check for anomalies
                if self.local_settings.getAnomaliesFlag():
                    specificConfig = fileManager.findFiles(dataSource, split[-2]+'.cdp' ,cdPath)
                    self.specConfigPath = os.path.join(self.temp_dir , str(specificConfig[0].getId()))
                    ContentUtils.writeToFile(specificConfig[0], File(self.specConfigPath))
                    # ETag anomalies
                    stmt = dbConn.createStatement()
                    etag_anomalies_content = stmt.executeQuery("select hex(Id) 'Id', ETag from SmartLookup where SmartLookup.ETag > (select Value from ManualSequence)")                    
                    self.checkForAnomalies(etag_anomalies_content,file,blackboard,skCase)
                    # Payload anomalies
                    stmt = dbConn.createStatement()
                    payload_anomalies_content = stmt.executeQuery("select hex(Id) 'Id', OriginalPayload, Payload from SmartLookup where ifnull(Payload, '') != ifnull(OriginalPayload, '')")
                    self.checkForPayloadAnomalies(payload_anomalies_content, file, blackboard, skCase)
                    # Update Timestamp anomalies
                    if specificConfig:
                        stmt = dbConn.createStatement()
                        db_update_timestamp = stmt.executeQuery("select Value from Metadata where Key = 'DatabaseInstanceIdUpdateTime'")
                        self.checkForUpdateTimestampAnomalies(db_update_timestamp, file, blackboard, skCase)
                #get configs   
                self.extractConfigFileInfo(file,blackboard,skCase)
            except SQLException as e:
                self.log(
                    Level.INFO, "Error querying database for smartlookup table (" + e.getMessage() + ")")
                continue
            try:
                dbConn.close()
            except:
                None
        
        return IngestModule.ProcessResult.OK

    def checkForAnomalies(self, tableContent, file, blackboard, skCase):
        try:
            isEmpty = True
            while tableContent.next():
                isEmpty =False
                art = file.newArtifact(self.etag_art.getTypeID())
                for name in self.etag_names_list:
                    foo = tableContent.getString(name)
                    self.log(Level.INFO, "NAME:" + name)
                    if(foo is None):
                        foo = "N/A"
                    art.addAttribute(BlackboardAttribute(self.generic_att[str(name)], WintenTimelineIngestModuleFactory.moduleName, foo.encode('utf-8')))
                self.index_artifact(blackboard, art, self.etag_art)
            if isEmpty:
                self.log(Level.INFO, "ETag anomalies not found")
                art = file.newArtifact(self.etag_art.getTypeID())
                art.addAttribute(BlackboardAttribute(self.generic_att['Id'], WintenTimelineIngestModuleFactory.moduleName, "No results found"))
                art.addAttribute(BlackboardAttribute(self.generic_att['ETag'], WintenTimelineIngestModuleFactory.moduleName, "No results found"))
                self.index_artifact(blackboard, art, self.etag_art)
        except Exception as e:
            self.log(Level.SEVERE, str(e))
            return None


    def checkForPayloadAnomalies(self, tableContent, file, blackboard, skCase):
        try:
            isEmpty = True
            while tableContent.next():
                isEmpty = False
                art = file.newArtifact(self.payload_art.getTypeID())
                for name in self.payload_names_list:
                    foo = tableContent.getString(name)
                    self.log(Level.INFO, "NAME:" + name)
                    if(foo is None):
                        foo = "N/A"
                    art.addAttribute(BlackboardAttribute(self.generic_att[str(name)], WintenTimelineIngestModuleFactory.moduleName, foo.encode('utf-8')))
                self.index_artifact(blackboard, art, self.payload_art)
            if isEmpty:
                self.log(Level.INFO, "Payload anomalies not found")
                art = file.newArtifact(self.payload_art.getTypeID())
                art.addAttribute(BlackboardAttribute(self.generic_att['Id'], WintenTimelineIngestModuleFactory.moduleName, "No results found"))
                art.addAttribute(BlackboardAttribute(self.generic_att['OriginalPayload'], WintenTimelineIngestModuleFactory.moduleName, "No results found"))
                art.addAttribute(BlackboardAttribute(self.generic_att['Payload'], WintenTimelineIngestModuleFactory.moduleName, "No results found"))
                self.index_artifact(blackboard, art, self.payload_art)
        except Exception as e:
            self.log(Level.SEVERE, str(e))
            return None

    def checkForUpdateTimestampAnomalies(self, tableContent, file, blackboard, skCase):
        try:
            with open(self.specConfigPath) as f:
                data= f.read()
                j = json.loads(data.decode('utf-8-sig').encode('utf-8'))
                date_on_config = j['AfcDatabaseSettings']['LastUpdated']

            art = file.newArtifact(self.update_timestamp_art.getTypeID())
            foo = tableContent.getString('Value')
            self.log(Level.INFO, "Date on Metadata table (before parsing): " + foo)
            date_saved_on_database = time.strftime('%H:%M:%S %Y-%m-%d', time.strptime(foo, '%Y-%m-%dT%H:%M:%S.%fZ'))
            self.log(Level.INFO, "Date on Metadata table (after parsing): " + date_saved_on_database)
            if foo is None:
                foo = "N/A"
            art.addAttribute(BlackboardAttribute(self.date_on_db, WintenTimelineIngestModuleFactory.moduleName, date_saved_on_database))
            self.index_artifact(blackboard, art, self.update_timestamp_art)
            art.addAttribute(BlackboardAttribute(self.date_on_config_file, WintenTimelineIngestModuleFactory.moduleName, date_on_config))
            self.index_artifact(blackboard, art, self.update_timestamp_art)
        except Exception as e:
            self.log(Level.SEVERE, str(e))
            return None
    def extractConfigFileInfo(self,file,blackboard,skCase):
        try:
            if self.cdpconfigPath == 0:
                return
            with open(self.cdpconfigPath) as f:
                data = f.read()
                j = json.loads(data.decode('utf-8-sig').encode('utf-8'))
                coll = 'Disabled' if j['AfcPrivacySettings']['PublishUserActivity'] else 'Enabled'
                syncCloud = 'Disabled' if j['AfcPrivacySettings']['UploadUserActivity'] else 'Enabled'
                listUsers = j['ActivityStoreInfo']
                for user in listUsers:
                    art= file.newArtifact(self.config_art.getTypeID())
                    userActive = 'Enabled' if user['active'] else 'Disabled'
                    userid = user['stableUserId'].encode('utf-8')
                    art.addAttribute(BlackboardAttribute(self.cfg_userId_att,WintenTimelineIngestModuleFactory.moduleName,userid))                    
                    art.addAttribute(BlackboardAttribute(self.cfg_active_att,WintenTimelineIngestModuleFactory.moduleName,userActive))
                    art.addAttribute(BlackboardAttribute(self.cfg_collect_att,WintenTimelineIngestModuleFactory.moduleName,coll))
                    art.addAttribute(BlackboardAttribute(self.cfg_up_to_cloud_att,WintenTimelineIngestModuleFactory.moduleName,syncCloud))
                    self.index_artifact(blackboard,art,self.config_art)
        except Exception as e:
            self.log(Level.SEVERE, str(e))
            return None


    def extractRawDataFromDB(self, tableContent, file, blackboard, skCase):
        try:
            while tableContent.next():
                art = file.newArtifact(self.raw_data_art.getTypeID())
                for name in self.raw_names_list:
                    if(name in DATETIME_FIELDS):
                        foo = tableContent.getInt(name)
                        if(foo is None):
                            foo = "N/A"
                        else:
                            foo = time.strftime(
                                '%H:%M:%S %Y-%m-%d', time.localtime(long(foo)))
                        art.addAttribute(BlackboardAttribute(
                            self.generic_att[str(name)], WintenTimelineIngestModuleFactory.moduleName, foo))
                    else:
                        foo = tableContent.getString(name)
                        if(foo is None):
                            foo = "N/A"
                        art.addAttribute(BlackboardAttribute(self.generic_att[str(name)], WintenTimelineIngestModuleFactory.moduleName, foo.encode('utf-8')))
                self.index_artifact(blackboard, art, self.raw_data_art)
        except Exception as e:
            self.log(Level.SEVERE, str(e))
            return None


    def extractProcessedData(self, tableContent, file, blackboard, skCase):
        try:
            while tableContent.next():
                art = file.newArtifact(self.proc_data_art.getTypeID())
                for name in self.proc_names_list:
                    if(name in DATETIME_FIELDS):
                        foo = tableContent.getInt(name)
                        if(foo is None):
                            foo = "N/A"
                        else:
                            foo = time.strftime(
                                '%H:%M:%S %Y-%m-%d', time.localtime(long(foo)))
                        art.addAttribute(BlackboardAttribute(self.generic_att[str(name)], WintenTimelineIngestModuleFactory.moduleName, foo))
                    else:
                        foo = tableContent.getString(name)
                        if(foo is None):
                            foo = "N/A"
                            art.addAttribute(BlackboardAttribute(self.generic_att[str(name)], WintenTimelineIngestModuleFactory.moduleName, foo.encode('utf-8')))
                        else:
                            if(name == 'AppId'):
                                appIdBlob = json.loads(foo)
                                application = str(appIdBlob[0]['application'])
                                platform = str(appIdBlob[0]['platform'])
                                art.addAttribute(BlackboardAttribute(self.json_app_att, WintenTimelineIngestModuleFactory.moduleName, application))
                                art.addAttribute(BlackboardAttribute(self.json_platform_att, WintenTimelineIngestModuleFactory.moduleName, platform))
                            elif(name == 'Payload'):
                                payloadBlob = json.loads(foo)
                                file_or_urlOpened = 'N/A'
                                used_program = 'N/A'
                                timezone = 'N/A'
                                if(tableContent.getString('ActivityType') == '5'):
                                    file_or_urlOpened = payloadBlob['displayText']
                                    used_program = payloadBlob['appDisplayName']
                                else:
                                    timezone = payloadBlob['userTimezone']
                                art.addAttribute(BlackboardAttribute(self.json_file_or_url_opened_att, WintenTimelineIngestModuleFactory.moduleName, file_or_urlOpened))
                                art.addAttribute(BlackboardAttribute(self.json_used_program_att, WintenTimelineIngestModuleFactory.moduleName, used_program))
                                art.addAttribute(BlackboardAttribute(self.json_timezone_att, WintenTimelineIngestModuleFactory.moduleName, timezone))
                            elif(name == 'ActivityStatus'):
                                if foo == '1':
                                    art.addAttribute(BlackboardAttribute(self.generic_att[str(name)], WintenTimelineIngestModuleFactory.moduleName, 'Active'))
                                elif foo =='2':
                                    art.addAttribute(BlackboardAttribute(self.generic_att[str(name)], WintenTimelineIngestModuleFactory.moduleName, 'Updated'))
                                elif foo == '3':
                                    art.addAttribute(BlackboardAttribute(self.generic_att[str(name)], WintenTimelineIngestModuleFactory.moduleName, 'Deleted'))
                                else:
                                    art.addAttribute(BlackboardAttribute(self.generic_att[str(name)], WintenTimelineIngestModuleFactory.moduleName, 'Ignored'))
                            elif name == 'PlatformDeviceId' and self.local_settings.getRegistryFlag():
                                name_val = tableContent.getString('PlatformDeviceId')
                                if name_val in self.regValues:
                                    art.addAttribute(BlackboardAttribute(self.device_name, WintenTimelineIngestModuleFactory.moduleName, self.regValues[name_val][0]))
                                    art.addAttribute(BlackboardAttribute(self.device_model, WintenTimelineIngestModuleFactory.moduleName, self.regValues[name_val][1]))
                                    art.addAttribute(BlackboardAttribute(self.device_maker, WintenTimelineIngestModuleFactory.moduleName, self.regValues[name_val][2]))
                                    art.addAttribute(BlackboardAttribute(self.device_type, WintenTimelineIngestModuleFactory.moduleName, self.regValues[name_val][3]))
                                    
                                else:
                                    hive = Registry.Registry(self.ntuserPath)
                                    key = hive.open("Software\\Microsoft\\Windows\\CurrentVersion\\TaskFlow\\DeviceCache\\"+name_val)
                                    aux = {1:"Xbox One", 6:"Apple iPhone", 7:"Apple iPad", 8:"Android device", 9:"Windows 10 Desktop", 11:"Windows 10 Phone", 12:"Linux device", 13:"Windows  IoT", 14:"Surface Hub", 15:"Windows Laptop"}                                
                                    listVals = []

                                    for keyname in ['DeviceName','DeviceModel','DeviceMake']: #this is some monkey-level fix for weird decoding
                                        charList  = []
                                        byteString = bytes(key[keyname].value().encode('utf-16be'))                                                                  
                                        for c in byteString:
                                            if c in stringModule.printable:
                                                charList.append(c)                                            
                                        stringFixed = ''.join(charList)
                                        self.log(Level.INFO, stringFixed)
                                        listVals.append(stringFixed)
                                        
                                    listVals.append(aux[key['DeviceType'].value()].encode('utf-8'))
                                    art.addAttribute(BlackboardAttribute(self.device_name, WintenTimelineIngestModuleFactory.moduleName,  listVals[0]))
                                    art.addAttribute(BlackboardAttribute(self.device_model, WintenTimelineIngestModuleFactory.moduleName, listVals[1]))
                                    art.addAttribute(BlackboardAttribute(self.device_maker, WintenTimelineIngestModuleFactory.moduleName, listVals[2]))
                                    art.addAttribute(BlackboardAttribute(self.device_type, WintenTimelineIngestModuleFactory.moduleName,  listVals[3]))
                                    self.regValues[name_val] = listVals
                            else:
                                art.addAttribute(BlackboardAttribute(self.generic_att[str(name)], WintenTimelineIngestModuleFactory.moduleName, foo.encode('utf-8')))
                                
                self.index_artifact(blackboard, art, self.proc_data_art)
        except Exception as e:
            self.log(Level.SEVERE, str(e))
            return None
   

class Process_timelineWithUISettings(IngestModuleIngestJobSettings):
    serialVersionUID = 1L
    
    def __init__(self):
        self.flag = False
        self.flag1 = False
        self.flag2 = False

    def getVersionNumber(self):
        return serialVersionUID

    # TODO: Define getters and settings for data you want to store from UI
    def getRawFlag(self):
        return self.flag

    def setFlag(self, flag):
        self.flag = flag

    def getRegistryFlag(self):
        return self.flag1

    def setFlag1(self, flag1):
        self.flag1 = flag1

    def getAnomaliesFlag(self):
        return self.flag2

    def setFlag2(self, flag2):
        self.flag2 = flag2

# UI that is shown to user for each ingest job so they can configure the job.
# TODO: Rename this


class Process_AmcacheWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
    # Note, we can't use a self.settings instance variable.
    # Rather, self.local_settings is used.
    # https://wiki.python.org/jython/UserGuide#javabean-properties
    # Jython Introspector generates a property - 'settings' on the basis
    # of getSettings() defined in this class. Since only getter function
    # is present, it creates a read-only 'settings' property. This auto-
    # generated read-only property overshadows the instance-variable -
    # 'settings'

    # We get passed in a previous version of the settings so that we can
    # prepopulate the UI
    # TODO: Update this for your UI
    def __init__(self, settings):
        self.local_settings = settings
        self.initComponents()
        self.customizeComponents()

    # TODO: Update this for your UI
    def checkBoxEvent(self, event):
        if self.checkbox.isSelected():
            self.local_settings.setFlag(True)
        else:
            self.local_settings.setFlag(False)
        if self.checkbox1.isSelected():
            self.local_settings.setFlag1(True)
        else:
            self.local_settings.setFlag1(False)
        if self.checkbox2.isSelected():
            self.local_settings.setFlag2(True)
        else:
            self.local_settings.setFlag2(False)

    # TODO: Update this for your UI

    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        # self.setLayout(GridLayout(0,1))
        self.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        self.panel1 = JPanel()
        self.panel1.setLayout(BoxLayout(self.panel1, BoxLayout.Y_AXIS))
        self.panel1.setAlignmentY(JComponent.LEFT_ALIGNMENT)
        self.checkbox = JCheckBox(
            "Extract raw table", actionPerformed=self.checkBoxEvent)
        self.checkbox1 = JCheckBox(
            "Search ntuser.dat for matches", actionPerformed=self.checkBoxEvent)
        self.checkbox2 = JCheckBox(
            "Search for date-time anomalies (this may take a few minutes more)", actionPerformed=self.checkBoxEvent)
        self.panel1.add(self.checkbox)
        self.panel1.add(self.checkbox1)
        self.panel1.add(self.checkbox2)
        self.add(self.panel1)

    # TODO: Update this for your UI

    def customizeComponents(self):
        self.checkbox.setSelected(self.local_settings.getRawFlag())
        self.checkbox1.setSelected(self.local_settings.getRegistryFlag())
        self.checkbox2.setSelected(self.local_settings.getAnomaliesFlag())

    # Return the settings used
    def getSettings(self):
        return self.local_settings