import os
import shutil
import pandas as pd
from sklearn.preprocessing import MultiLabelBinarizer
import xml.etree.ElementTree as ET
import sklearn.svm
import sklearn.cluster
import sklearn.linear_model
import sklearn.model_selection
import sklearn.tree
import lightgbm
import sklearn.metrics
from sklearn.decomposition import PCA
import matplotlib.pyplot
import numpy as np

def parseAndDecompileApks(filePath,chdirectory):
    apkTool = "C:/Users/jnoronha/apktool.jar"
    for fileName in os.listdir(filePath):
        curFilePath = os.path.join(filePath, fileName)
        os.chdir(chdirectory)
        if curFilePath.endswith('.apk'):
            os.system("java -jar " + apkTool + " d " + curFilePath)


def parseAndGetAndroidManifest(directoryPath, outputPath):
    for directory in os.listdir(directoryPath):
        if directory == '.DS_Store':
            continue
        inputFilePath = '/'+directory+'/AndroidManifest.xml'
        outputFileName = '/'+directory+'_AndroidManifest.xml'
        if(os.path.exists(directoryPath+inputFilePath)):
          shutil.copyfile(directoryPath+inputFilePath, outputPath+outputFileName)

def calculatefscore(expected,actual):
  TP=0
  FP=0
  FN=0
  TN=0
  for i in range(len(expected)):
    if actual[i]>=1 and expected[i]==1:
      TP=TP+1
    elif actual[i]==1 and expected[i]==0:
      FP=FP+1
    elif actual[i]==0 and expected[i]==1:
      FN=FN+1
    

  fscore=2*TP/(2*TP+FP+FN)
  print(TP,FP,FN)
  return(fscore)

def predict(model,trainSet,trainRes,testSet):
  model.fit(trainSet,trainRes)
  predictions=model.predict(testSet)
  return(predictions)


#parseAndDecompileApks('C:/Users/jnoronha/Documents/siftwaresecurity/malware','C:/Users/jnoronha/Documents/siftwaresecurity/extractedmalware')
#parseAndDecompileApks('C:/Users/jnoronha/Documents/siftwaresecurity/benign','C:/Users/jnoronha/Documents/siftwaresecurity/extractedbenign')
#parseAndGetAndroidManifest('C:/Users/jnoronha/Documents/siftwaresecurity/extractedmalware', 'C:/Users/jnoronha/Documents/siftwaresecurity/extractedmanifestmalign')
parseAndGetAndroidManifest('C:/Users/jnoronha/Documents/siftwaresecurity/extractedbenign', 'C:/Users/jnoronha/Documents/siftwaresecurity/extractedmanifestbenign')

malPermissionsMap = pd.DataFrame(columns=['AppName', 'Permissions','isBenign'])
malPermissionsMapFeat1 = pd.DataFrame(columns=['AppName','Permissions','Receiver','isBenign'])
malPermissionsMapFeat2 = pd.DataFrame(columns=['AppName','Permissions','Receiver','MetaData','isBenign'])

mal_dir = "C:/Users/jnoronha/Documents/siftwaresecurity/extractedmanifestmalign"
for fileName in os.listdir(mal_dir):
  if fileName == '.DS_Store':
    continue
  try:
    androidManifest = ET.parse(mal_dir+'/'+fileName)
  except ET.ParseError:
    continue
  appName = fileName[:len(fileName)-20]
  permissionsList = []
  receiverList= []
  for permission in androidManifest.findall('uses-permission'):
    permissionsList.append(permission.attrib['{http://schemas.android.com/apk/res/android}name'])
  for receiver in androidManifest.findall('application/receiver'):
    receiverList.append(receiver.attrib['{http://schemas.android.com/apk/res/android}name'])
  malPermissionsMap.loc[len(malPermissionsMap.index)] = [appName, permissionsList,0]
  malPermissionsMapFeat1.loc[len(malPermissionsMapFeat1.index)] = [appName,permissionsList,receiverList,0]

benPermissionsMap = pd.DataFrame(columns=['AppName', 'Permissions','isBenign'])
benPermissionsMapFeat1 = pd.DataFrame(columns=['AppName','Permissions','Receiver','isBenign'])
benPermissionsMapFeat2 = pd.DataFrame(columns=['AppName','Permissions','Receiver','MetaData','isBenign'])

ben_dir = "C:/Users/jnoronha/Documents/siftwaresecurity/extractedmanifestbenign"
for fileName in os.listdir(ben_dir):
  if fileName == '.DS_Store':
    continue
  try:
    androidManifest = ET.parse(ben_dir+'/'+fileName)
  except ET.ParseError:
    continue
  appName = fileName[:len(fileName)-20]
  permissionsList = []
  receiverList= []
  for permission in androidManifest.findall('uses-permission'):
    permissionsList.append(permission.attrib['{http://schemas.android.com/apk/res/android}name'])
  for receiver in androidManifest.findall('application/receiver'):
    receiverList.append(receiver.attrib['{http://schemas.android.com/apk/res/android}name'])
  benPermissionsMap.loc[len(benPermissionsMap.index)] = [appName, permissionsList,1]
  benPermissionsMapFeat1.loc[len(benPermissionsMapFeat1.index)] = [appName,permissionsList,receiverList,1]
permissionsMap=pd.concat([benPermissionsMap,malPermissionsMap],ignore_index=True)
permissionsMapFeat1=pd.concat([benPermissionsMapFeat1,malPermissionsMapFeat1],ignore_index=True)

multiLableBinarizer = MultiLabelBinarizer(sparse_output=True)
permissionsMap = permissionsMap.join(pd.DataFrame.sparse.from_spmatrix(multiLableBinarizer.fit_transform(permissionsMap.pop('Permissions')),index=permissionsMap.index,columns=multiLableBinarizer.classes_))
permissionsMap = permissionsMap.drop('AppName', axis=1)
isBen=permissionsMap.isBenign
permissionsMap = permissionsMap.drop('isBenign', axis=1)
permissionsMap=permissionsMap.to_numpy()
isBen=isBen.to_numpy()

multiLableBinarizer = MultiLabelBinarizer(sparse_output=True)
permissionsMapFeat1 = permissionsMapFeat1.join(pd.DataFrame.sparse.from_spmatrix(multiLableBinarizer.fit_transform(permissionsMapFeat1.pop('Permissions')),index=permissionsMapFeat1.index,columns=multiLableBinarizer.classes_))
permissionsMapFeat1 = permissionsMapFeat1.join(pd.DataFrame.sparse.from_spmatrix(multiLableBinarizer.fit_transform(permissionsMapFeat1.pop('Receiver')),index=permissionsMapFeat1.index,columns=multiLableBinarizer.classes_))
permissionsMapFeat1 = permissionsMapFeat1.drop('AppName', axis=1)
isBenFeat1=permissionsMapFeat1.isBenign
permissionsMapFeat1 = permissionsMapFeat1.drop('isBenign', axis=1)
permissionsMapFeat1=permissionsMapFeat1.to_numpy()
isBenFeat1=isBenFeat1.to_numpy()

trainSet,testSet,trainRes,testRes = sklearn.model_selection.train_test_split(permissionsMapFeat1,isBen, test_size=0.2)