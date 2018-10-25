# This python autopsy module will export the Amcache Regiatry Hive and then call
# the command line version of the Export_Amcache program.  A sqlite database that
# contains the Amcache information is created then imported into the extracted
# view section of Autopsy.
#
# Contact: Mark McKinnon [Mark [dot] McKinnon <at> Davenport [dot] edu]
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# Amcache module to parse the amcache registry hive.
# June 2016
# 
# Comments 
#   Version 1.0 - Initial version - June 2016
#   Version 1.1 - Added custom artifacts and attributes - Aug 31, 2016
# 

import jarray
import inspect
import os
import subprocess

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


from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
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
            raise IllegalArgumentException("Expected settings argument to be instanceof SampleIngestModuleSettings")
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
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.art_list =[]
        
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
        
        if self.local_settings.getFlag():
            self.List_Of_tables.append('associated_file_entries')
        if self.local_settings.getFlag1():
            self.List_Of_tables.append('program_entries')
        if self.local_settings.getFlag2():
            self.List_Of_tables.append('unassociated_programs')
        self.temp_dir = Case.getCurrentCase().getTempDirectory()
        self.create_temp_directory("\WTA")        

        
        pass

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
        self.generic_art = {}

        for file in files:
            wtaDbPath = os.path.join(self.temp_dir + "\WTA", str(file.getId()))
            ContentUtils.writeToFile(file, File(wtaDbPath))
            try: 
               Class.forName("org.sqlite.JDBC").newInstance()
               dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % wtaDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            try:              
                stmt = dbConn.createStatement()
                resultSetTableNames = stmt.executeQuery("Select tbl_name from SQLITE_MASTER;")

                while resultSetTableNames.next():
                    table_name = resultSetTableNames.getString("tbl_name")
                    self.log(Level.INFO, "Result get information from table " + table_name + " ")                
                    self.generic_art[table_name] = self.create_artifact_type("TSK_WTA_"+ table_name.upper(),  table_name+" table", skCase)
                    col_name_type ={}
                    generic_atts = {}
                 
                    resColNames = stmt.executeQuery("PRAGMA table_info('"+ table_name +"')")
                    while resColNames.next():
                        
                        col_name = resColNames.getString("name")
                        col_type = resColNames.getString("type")
                        

                        if(col_type == 'TEXT' or col_type == "DATETIME"):
                            generic_atts['TSK_'+table_name.upper()+"_"+col_name.upper()] = self.create_attribute_type('TSK_'+table_name.upper()+"_"+col_name.upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, col_name, skCase)
                            col_name_type[col_name] = col_type
                        elif(col_type == 'INT'):
                            generic_atts['TSK_'+table_name.upper()+"_"+col_name.upper()] = self.create_attribute_type('TSK_'+table_name.upper()+"_"+col_name.upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, col_name, skCase)
                            col_name_type[col_name] = col_type

                        self.log(Level.INFO, "Result get information from table " + table_name + " cols name and type"+col_name+" "+col_type)
                    
                    resData = stmt.executeQuery("Select * from '"+table_name+"'")
                    while resData.next():
                        art = file.newArtifact(self.generic_art[table_name].getTypeID())
                        for name, c_type in col_name_type.iteritems():
                            if(c_type == 'INT'):
                                self.log(Level.INFO, "SUPPOSED TO BE INT,  cols name and type "+name+" "+   c_type)
                                art.addAttribute(BlackboardAttribute(generic_atts['TSK_'+table_name.upper()+"_"+name.upper()], WintenTimelineIngestModuleFactory.moduleName, str(resData.getInt(name))))
                            if(c_type == 'TEXT' ):
                                self.log(Level.INFO, "SUPPOSED TO BE text,  cols name and type "+name+" "+   c_type)
                                art.addAttribute(BlackboardAttribute(generic_atts['TSK_'+table_name.upper()+"_"+name.upper()], WintenTimelineIngestModuleFactory.moduleName, str(resData.getString(name))))
                            if(c_type == "DATETIME"):
                                self.log(Level.INFO, "SUPPOSED TO BE datetime,  cols name and type "+name+" "+   c_type)
                                art.addAttribute(BlackboardAttribute(generic_atts['TSK_'+table_name.upper()+"_"+name.upper()], WintenTimelineIngestModuleFactory.moduleName, str(resData.getString(name))))
                        self.index_artifact(blackboard, art, self.generic_art[table_name])
       
            except SQLException as e:
                    self.log(Level.INFO, "Error querying database for timeline table (" + e.getMessage() + ")")
                    return IngestModule.ProcessResult.OK
        return IngestModule.ProcessResult.OK                
		
class Process_timelineWithUISettings(IngestModuleIngestJobSettings):
    serialVersionUID = 1L

    def __init__(self):
        self.flag = False
        self.flag1 = False
        self.flag2 = False

    def getVersionNumber(self):
        return serialVersionUID

    # TODO: Define getters and settings for data you want to store from UI
    def getFlag(self):
        return self.flag

    def setFlag(self, flag):
        self.flag = flag

    def getFlag1(self):
        return self.flag1

    def setFlag1(self, flag1):
        self.flag1 = flag1

    def getFlag2(self):
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
        #self.setLayout(GridLayout(0,1))
        self.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        self.panel1 = JPanel()
        self.panel1.setLayout(BoxLayout(self.panel1, BoxLayout.Y_AXIS))
        self.panel1.setAlignmentY(JComponent.LEFT_ALIGNMENT)
        self.checkbox = JCheckBox("Associate File Entries", actionPerformed=self.checkBoxEvent)
        self.checkbox1 = JCheckBox("Program Entries", actionPerformed=self.checkBoxEvent)
        self.checkbox2 = JCheckBox("Unassociated Programs", actionPerformed=self.checkBoxEvent)
        self.panel1.add(self.checkbox)
        self.panel1.add(self.checkbox1)
        self.panel1.add(self.checkbox2)
        self.add(self.panel1)
		


    # TODO: Update this for your UI
    def customizeComponents(self):
        self.checkbox.setSelected(self.local_settings.getFlag())
        self.checkbox1.setSelected(self.local_settings.getFlag1())
        self.checkbox2.setSelected(self.local_settings.getFlag2())

    # Return the settings used
    def getSettings(self):
        return self.local_settings

 