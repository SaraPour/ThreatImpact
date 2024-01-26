#!/usr/bin/env python
# coding: utf-8

import numpy as np
import pandas as pd
import re
import os
import sys


# Load STRIDE Threat List
# threatFile = Input get the threatlist, dfdfile and output file name from command prompt

threatFile = str(sys.argv[1])
sdFile = str(sys.argv[2])
attackFile = str(sys.argv[3])

tListData = pd.read_csv(threatFile , sep=',', header=0)

for i, row in tListData.iterrows():
    tListData.at[i, 'Interaction'] = re.sub("," , ";", row['Interaction'] )

#Run script to generate Source and Destination
os.system("./dfdquery export " + sdFile + " SourceDestination.csv")


# Load Source Destination info
sd = 'SourceDestination.csv'
sdList = pd.read_csv(sd , sep=',', header=None)

sdList.columns =['sno', 'Interaction', 'Source', 'SourceType', 'Destination', 'DestinationType']

sdList.drop('sno', axis=1, inplace=True)
sdList.columns = sdList.columns.str.strip()


#Count duplicates add flags
freq = sdList.groupby(['Interaction']).size().reset_index(name='count')
for i, row in freq.iterrows():
    sdList.loc[ sdList['Interaction'] == row['Interaction'], 'IFlag'] = row['count']

aList = tListData[['Id', 'Interaction', 'Category',  'Description', 'Title']].copy()
aList['Interaction'] = aList.Interaction.str.strip()


aList.rename(columns = {'Id':'ThreatID'}, inplace = True)
aList['RepeatedElseWhere'] = 'Null'
aList['RepeatedInCategory'] = 'Null'
aList['Effect'] = 'Null'
#aList.tail()


# Spoofing
aList['RepeatedElseWhere'] = np.where((aList['Category']== 'Spoofing'), np.where(aList['Description'].str.endswith("destination process."),True, False), aList['RepeatedElseWhere'])


# Tampering

aList['RepeatedElseWhere'] = np.where((aList['Category']== 'Tampering'), np.where(aList['Description'].str.endswith(" to the data store."), False, True), aList['RepeatedElseWhere'])    

# Elevation Of Privilege, Denial Of Service, Repudiation, Information Disclosure:  All False

falseCategories = {'Elevation Of Privilege', 'Denial Of Service', 'Repudiation', 'Information Disclosure'}
aList['RepeatedElseWhere'] = np.where((aList['Category'].isin(falseCategories)), False, aList['RepeatedElseWhere'])


# # RepeatedInCategory:

# Spoofing
aList['RepeatedInCategory'] = np.where((aList['Category'] == 'Spoofing') & (aList['Description'].str.endswith("destination process.")), 'Information Disclosure', aList['RepeatedInCategory'])
aList['RepeatedInCategory'] = np.where((aList['Category'] == 'Spoofing') & (aList['Description'].str.endswith("destination process.") == False), False,aList['RepeatedInCategory'])
aList['RepeatedInCategory'] = np.where((aList['Category'] == 'Tampering') & (aList['Description'].str.contains(r'(?=.*denial of service attack)(?=.*elevation of privilege attack)(?=.*information disclosure)',regex=True)), 'TBR' , aList['RepeatedInCategory'])
tp1 = aList.replace({'RepeatedInCategory': {'TBR':'Denial Of Service'}})
tp2 = aList[aList['RepeatedInCategory'].eq('TBR')].assign(RepeatedInCategory = 'Elevation Of Privilege').rename(lambda x: x + .5)
tp3 = aList[aList['RepeatedInCategory'].eq('TBR')].assign(RepeatedInCategory = 'Information Disclosure').rename(lambda x: x + .5)
aList = pd.concat([tp1, tp2, tp3]).sort_index().reset_index(drop=True)

#if the "repeated elsewhere" is F then value --> Null
aList['RepeatedInCategory'] = np.where((aList['Category'] == 'Tampering') & (aList['RepeatedElseWhere'] == False), False , aList['RepeatedInCategory'])

# Elevation Of Privilege, Denial Of Service, Repudiation, Information Disclosure:  All False

falseCategories = {'Elevation Of Privilege', 'Denial Of Service', 'Repudiation', 'Information Disclosure'}
aList['RepeatedInCategory'] = np.where(aList['Category'].isin(falseCategories), False, aList['RepeatedInCategory'])


# Effect

#Spoofing
aList['Effect'] = np.where((aList['Category'] == 'Spoofing'), np.where((aList['RepeatedElseWhere']), False, aList['Description']), aList['Effect'])     
tmpList = aList.copy()
for i, row in tmpList.iterrows():
    if (row['Category'] == 'Spoofing') & (row['RepeatedElseWhere'] == False) & ("instead of" in row['Description']):
        val1 = re.findall('may lead to (.*?) instead of', row['Description'])
        aList.at[ i, 'Effect'] = val1[0]
        
    if (row['Category'] == 'Spoofing') & (row['RepeatedElseWhere'] == False) & ("instead of" not in row['Description']):
        val2 = re.findall('may lead to (.*?) to', row['Description'])
        aList.at[ i, 'Effect'] = val2[0]

#Elevation Of Privilege, impersonate

aList['Effect'] = np.where((aList['Category'] == 'Elevation Of Privilege'), aList['Description'], aList['Effect'] )
tmpList = aList[['Effect']].copy()
tmpList['Effect'] = aList.Description.str.extract(r'(impersonate|change the flow of program execution|remotely execute code|Cross-site request forgery)' )
for i, row in tmpList.iterrows():
    if (pd.isna(row['Effect']) == False):
        aList.at[ i, 'Effect'] = row['Effect']
        
#Tampering
aList['Effect'] = np.where((aList['Category'] == 'Tampering'), np.where((aList['RepeatedElseWhere'] == False), 'Corruption', False), aList['Effect'])

# Denial of Service
aList['Effect'] = np.where((aList['Category'] == 'Denial Of Service') & (aList.Description.str.startswith('Does')), 'Resource consumption' , np.where((aList.Description.str.endswith('availability metric.')) & (aList['Category'] == 'Denial Of Service'), 'Crashes' , np.where (( aList.Description.str.endswith('trust boundary.')) & (aList['Category'] == 'Denial Of Service'), 'Prevent access to data store' , np.where((aList.Description.str.endswith('in either direction.')) & (aList['Category'] == 'Denial Of Service'), 'Interrupt data flowing', aList['Effect']))))

# Repudiation:
aList['Effect'] = np.where((aList['Category'] == 'Repudiation')  & ( aList.Title.str.startswith('External Entity')), 'Denies receving data', np.where((aList['Category'] == 'Repudiation')  & ( aList.Title.str.startswith('Data Store')), 'Potentially writing data',np.where((aList['Category'] == 'Repudiation')  & ( aList.Title.str.startswith('Potential')), 'Data Repudiation', aList['Effect'])))

# Information Disclosure:
aList['Effect'] = np.where((aList['Category'] == 'Information Disclosure')  & ( aList.Description.str.startswith('Improper')), 'Information not intended for disclosure', np.where((aList['Category'] == 'Information Disclosure')  &  (aList.Description.str.startswith('Improper') == False), 'Data Flow Sniffing', aList['Effect'] ))

# Source Destination
aList['IFlag'] = 'Null'
for i, row in sdList.iterrows():
    aList.loc[ aList['Interaction'] == row['Interaction'], 'IFlag'] = row['IFlag']

aList[ 'Source'] = 'Null'
aList[ 'SourceType'] = 'Null'
aList[ 'Destination'] = 'Null'
aList[ 'DestinationType'] = 'Null'

for i, row in sdList.iterrows():    
    if (row['IFlag'] == 1):
        aList.loc[ aList['Interaction'] == row['Interaction'], 'Source'] = row['Source']
        aList.loc[ aList['Interaction'] == row['Interaction'], 'SourceType'] = row['SourceType']
        aList.loc[ aList['Interaction'] == row['Interaction'], 'Destination'] = row['Destination']
        aList.loc[ aList['Interaction'] == row['Interaction'], 'DestinationType'] = row['DestinationType']

for j, aRow in aList.iterrows():
        
    if (aRow['IFlag'] > 1) & (aRow['Category'] == 'Spoofing') & (aRow['Description'].endswith("destination process.") == True) & (aRow['Source'] == 'Null') & (aRow['Destination'] == 'Null') :

        val = re.findall('information disclosure by (.*?) Consider', aRow['Description'])
        valS = val[0].rstrip('.')
        
        aList.at[ j, 'Source'] = valS        
        sType = sdList.loc[ (sdList['Source'] == valS), 'SourceType']
        aList.at[ j, 'SourceType'] = sType.iloc[0]
        
        val = aRow['Description'].split('may be')
        valD = val[0].rstrip(' ')
        
        aList.at[ j, 'Destination'] = valD
        dType = sdList.loc[ (sdList['Destination'] == valD), 'DestinationType']
        aList.at[ j, 'DestinationType'] = dType.iloc[0]

    if (aRow['IFlag'] > 1) & (aRow['Category'] == 'Spoofing') & (aRow['Description'].endswith("external entity.") == True) & (aRow['Source'] == 'Null') & (aRow['Destination'] == 'Null'):

        val = aRow['Description'].split('may be')
        valS = val[0].rstrip(' ')
        
        aList.at[ j, 'Source'] = valS
        sType = sdList.loc[ (sdList['Source'] == valS), 'SourceType']
        aList.at[ j, 'SourceType'] = sType.iloc[0]
        
        val = re.findall('unauthorized access to (.*?) Consider', aRow['Description'])
        valD = val[0].rstrip('. ')
        
        aList.at[ j, 'Destination'] = valD
        dType = sdList.loc[ (sdList['Destination'] == valD), 'DestinationType']
        aList.at[ j, 'DestinationType'] = dType.iloc[0]
        
    if (aRow['IFlag'] > 1) & (aRow['Category'] == 'Spoofing') & (aRow['Description'].endswith("source process.") == True) & (aRow['Source'] == 'Null') & (aRow['Destination'] == 'Null') :

        val = aRow['Description'].split('may be')
        valS = val[0].rstrip(' ')
        
        aList.at[ j, 'Source'] = valS
        sType = sdList.loc[ (sdList['Source'] == valS), 'SourceType']
        aList.at[ j, 'SourceType'] = sType.iloc[0]
        
        val = re.findall('unauthorized access to (.*?) Consider', aRow['Description'])
        valD = val[0].rstrip('.')
        
        aList.at[ j, 'Destination'] = valD
        dType = sdList.loc[ (sdList['Destination'] == valD), 'DestinationType']
        aList.at[ j, 'DestinationType'] = dType.iloc[0]
        
    if (aRow['IFlag'] > 1) & (aRow['Category'] == 'Spoofing') & (aRow['Description'].endswith("source data store.") == True) & (aRow['Source'] == 'Null') & (aRow['Destination'] == 'Null') :

        val = aRow['Description'].split('may be')
        valS = val[0].rstrip(' ')
        
        aList.at[ j, 'Source'] = valS
        sType = sdList.loc[ (sdList['Source'] == valS), 'SourceType']
        aList.at[ j, 'SourceType'] = sType.iloc[0]
        
        val = re.findall('data delivered to (.*?) Consider', aRow['Description'])
        valD = val[0].rstrip('.')
        
        aList.at[ j, 'Destination'] = valD
        dType = sdList.loc[ (sdList['Destination'] == valD), 'DestinationType']
        aList.at[ j, 'DestinationType'] = dType.iloc[0]
        
for j, aRow in aList.iterrows():
        
    if (aRow['IFlag'] > 1) & (aRow['Category'] == 'Denial Of Service') & (aRow['Description'].endswith("do timeout.") == True) & (aRow['Source'] == 'Null') & (aRow['Destination'] == 'Null') :

        val = re.findall('Does (.*?) or', aRow['Description'])
        valS = val[0].rstrip(' ')
        
        aList.at[ j, 'Source'] = valS       
        sType = sdList.loc[ (sdList['Source'] == valS), 'SourceType']
        aList.at[ j, 'SourceType'] = sType.iloc[0]
        val = re.findall('or (.*?) take explicit steps', aRow['Description'])
        valD = val[0].rstrip(' ')
        
        aList.at[ j, 'Destination'] = valD
        dType = sdList.loc[ (sdList['Destination'] == valD), 'DestinationType']
        aList.at[ j, 'DestinationType'] = dType.iloc[0]
        
for j, aRow in aList.iterrows():
        
    if (aRow['IFlag'] > 1) & (aRow['Category'] == 'Spoofing') & (aRow['Description'].endswith("destination data store.") == True) & (aRow['Source'] == 'Null') & (aRow['Destination'] == 'Null') :

        val = aRow['ThreatID'] + 1;
        
        valS = aList.loc[ (aList['ThreatID'] == val) & (aList['Effect'] == 'Resource consumption'), 'Source']
        sType = aList.loc[ (aList['ThreatID'] == val) & (aList['Effect'] == 'Resource consumption'), 'SourceType']

        if (valS.size >= 1):
            aList.at[ j, 'Source'] = valS.iloc[0]
            aList.at[ j, 'SourceType'] = sType.iloc[0]
       
        valD = aList.loc[ (aList['ThreatID'] == val) & (aList['Effect'] == 'Resource consumption'), 'Destination']
        dType = aList.loc[ (aList['ThreatID'] == val) & (aList['Effect'] == 'Resource consumption'), 'DestinationType']
        
        if (valD.size >= 1):
            aList.at[ j, 'Destination'] = valD.iloc[0]
            aList.at[ j, 'DestinationType'] = dType.iloc[0]

for j, aRow in aList.iterrows():

    if  (aRow['Category'] == 'Elevation Of Privilege') & (aRow['IFlag'] > 1) & (aRow['Source'] == 'Null') & (aRow['Destination'] == 'Null') & (aRow['Effect'] == 'impersonate'):
             
        val = re.findall('context of (.*?) in order', aRow['Description'])
        valS = val[0].rstrip(' ')
        
        aList.at[ j, 'Source'] = valS
        sType = sdList.loc[ (sdList['Source'] == valS), 'SourceType']
        aList.at[ j, 'SourceType'] = sType.iloc[0]
        
        val = aRow['Description'].split('may be')
        valD = val[0].rstrip(' ')
        
        aList.at[ j, 'Destination'] = valD
        dType = sdList.loc[ (sdList['Destination'] == valD), 'DestinationType']
        aList.at[ j, 'DestinationType'] = dType.iloc[0]
        
    if  (aRow['Category'] == 'Elevation Of Privilege') & (aRow['IFlag'] > 1) & (aRow['Source'] == 'Null') & (aRow['Destination'] == 'Null') & (aRow['Effect'] == 'remotely execute code'):          
    

        val = aRow['Description'].split('may be')
        valS = val[0].rstrip(' ')
        
        aList.at[ j, 'Source'] = valS
        sType = sdList.loc[ (sdList['Source'] == valS), 'SourceType']
        aList.at[ j, 'SourceType'] = sType.iloc[0]
        
        val = aRow['Description'].split('remotely execute code for ')
        valD = val[1].rstrip('.')

        aList.at[ j, 'Destination'] = valD
        dType = sdList.loc[ (sdList['Destination'] == valD), 'DestinationType']
        aList.at[ j, 'DestinationType'] = dType.iloc[0]
        
for j, aRow in aList.iterrows():

    if  (aRow['Category'] == 'Elevation Of Privilege') & (aRow['IFlag'] > 1) & (aRow['Source'] == 'Null') & (aRow['Destination'] == 'Null') & (aRow['Effect'] == 'change the flow of program execution'):
        val = aRow['ThreatID'] - 1;
        valS = aList.loc[ (aList['ThreatID'] == val) , 'Source']
        sType = aList.loc[ (aList['ThreatID'] == val) , 'SourceType']

        if (valS.size >= 1):
            aList.at[ j, 'Source'] = valS.iloc[0]
            aList.at[ j, 'SourceType'] = sType.iloc[0]
        
        valD = aList.loc[ (aList['ThreatID'] == val) , 'Destination']
        dType = aList.loc[ (aList['ThreatID'] == val) , 'DestinationType']
        
        if (valD.size >= 1):
            aList.at[ j, 'Destination'] = valD.iloc[0]
            aList.at[ j, 'DestinationType'] = dType.iloc[0]

for j, aRow in aList.iterrows():

    if  (aRow['Category'] == 'Elevation Of Privilege') & (aRow['IFlag'] > 1) & (aRow['Source'] == 'Null') & (aRow['Destination'] == 'Null') & (aRow['Effect'] == 'Cross-site request forgery'):
        val = aRow['ThreatID'] - 1;
        valS = aList.loc[ (aList['ThreatID'] == val) , 'Source']
        sType = aList.loc[ (aList['ThreatID'] == val) , 'SourceType']

        if (valS.size >= 1):
            aList.at[ j, 'Source'] = valS.iloc[0]
            aList.at[ j, 'SourceType'] = sType.iloc[0]
        
        valD = aList.loc[ (aList['ThreatID'] == val) , 'Destination']
        dType = aList.loc[ (aList['ThreatID'] == val) , 'DestinationType']
        
        if (valD.size >= 1):
            aList.at[ j, 'Destination'] = valD.iloc[0]
            aList.at[ j, 'DestinationType'] = dType.iloc[0]

for j, aRow in aList.iterrows():

    if  (aRow['Category'] == 'Denial Of Service') & (aRow['IFlag'] > 1) & (aRow['Source'] == 'Null') & (aRow['Destination'] == 'Null') & (aRow['Effect'] == 'Interrupt data flowing'):
        val = aRow['ThreatID'] + 1;
        
        valS  = aList.loc[ (aList['ThreatID'] == val) & (aList['Category'] == 'Elevation Of Privilege'), 'Source']
        sType = aList.loc[ (aList['ThreatID'] == val) & (aList['Category'] == 'Elevation Of Privilege'), 'SourceType']

        if (valS.size >= 1):
            aList.at[ j, 'Source'] = valS.iloc[0]
            aList.at[ j, 'SourceType'] = sType.iloc[0]
        
        valD = aList.loc[ (aList['ThreatID'] == val) & (aList['Category'] == 'Elevation Of Privilege'), 'Destination']
        dType = aList.loc[ (aList['ThreatID'] == val) & (aList['Category'] == 'Elevation Of Privilege'), 'DestinationType']
        
        if (valD.size >= 1):
            aList.at[ j, 'Destination'] = valD.iloc[0]
            aList.at[ j, 'DestinationType'] = dType.iloc[0]


for j, aRow in aList.iterrows():

    if  (aRow['Category'] == 'Denial Of Service') & (aRow['IFlag'] > 1) & (aRow['Source'] == 'Null') & (aRow['Destination'] == 'Null') & (aRow['Effect'] == 'Crashes'):
        val = aRow['ThreatID'] + 1;
        
        valS = aList.loc[ (aList['ThreatID'] == val) & (aList['Effect'] == 'Interrupt data flowing'), 'Source']
        sType = aList.loc[ (aList['ThreatID'] == val) & (aList['Effect'] == 'Interrupt data flowing') , 'SourceType']

        if (valS.size >= 1):
            aList.at[ j, 'Source'] = valS.iloc[0]
            aList.at[ j, 'SourceType'] = sType.iloc[0]
        
        valD = aList.loc[ (aList['ThreatID'] == val) & (aList['Effect'] == 'Interrupt data flowing'), 'Destination']
        dType = aList.loc[ (aList['ThreatID'] == val) & (aList['Effect'] == 'Interrupt data flowing') , 'DestinationType']
        
        if (valD.size >= 1):
            aList.at[ j, 'Destination'] = valD.iloc[0]
            aList.at[ j, 'DestinationType'] = dType.iloc[0]

for j, aRow in aList.iterrows():

    if  (aRow['Category'] == 'Tampering') & (aRow['IFlag'] > 1) & (aRow['Source'] == 'Null') & (aRow['Destination'] == 'Null') & (aRow['Effect'] == 'False'):
        val = aRow['ThreatID'] - 1;
        
        valS = aList.loc[ (aList['ThreatID'] == val) , 'Source']
        sType = aList.loc[ (aList['ThreatID'] == val) , 'SourceType']

        if (valS.size >= 1):
            aList.at[ j, 'Source'] = valS.iloc[0]
            aList.at[ j, 'SourceType'] = sType.iloc[0]
        
        valD = aList.loc[ (aList['ThreatID'] == val) , 'Destination']
        dType = aList.loc[ (aList['ThreatID'] == val) , 'DestinationType']
        
        if (valD.size >= 1):
            aList.at[ j, 'Destination'] = valD.iloc[0]
            aList.at[ j, 'DestinationType'] = dType.iloc[0]

for j, aRow in aList.iterrows():

    if  (aRow['Category'] == 'Repudiation') & (aRow['IFlag'] > 1) & (aRow['Source'] == 'Null') & (aRow['Destination'] == 'Null') :
        val = aRow['ThreatID'] - 1;
        
        valS = aList.loc[ (aList['ThreatID'] == val) & (aList['Category'] == 'Tampering'), 'Source']
        sType = aList.loc[ (aList['ThreatID'] == val) & (aList['Category'] == 'Tampering'), 'SourceType']

        if (valS.size >= 1):
            aList.at[ j, 'Source'] = valS.iloc[0]
            aList.at[ j, 'SourceType'] = sType.iloc[0]
        
        valD = aList.loc[ (aList['ThreatID'] == val) & (aList['Category'] == 'Tampering'), 'Destination']
        dType = aList.loc[ (aList['ThreatID'] == val) & (aList['Category'] == 'Tampering'), 'DestinationType']
        
        if (valD.size >= 1):
            aList.at[ j, 'Destination'] = valD.iloc[0]
            aList.at[ j, 'DestinationType'] = dType.iloc[0]


for j, aRow in aList.iterrows():

     if  (aRow['Category'] == 'Information Disclosure') & (aRow['IFlag'] > 1) & (aRow['Description'].endswith("encrypting the data flow.") == True) & (aRow['Source'] == 'Null') & (aRow['Destination'] == 'Null') :
        val = aRow['ThreatID'] + 1;
        
        valS = aList.loc[ (aList['ThreatID'] == val) & (aList['Category'] == 'Denial Of Service'), 'Source']
        sType = aList.loc[ (aList['ThreatID'] == val) & (aList['Category'] == 'Denial Of Service'), 'SourceType']

        if (valS.size >= 1):
            aList.at[ j, 'Source'] = valS.iloc[0]
            aList.at[ j, 'SourceType'] = sType.iloc[0]
        
        valD = aList.loc[ (aList['ThreatID'] == val) & (aList['Category'] == 'Denial Of Service'), 'Destination']
        dType = aList.loc[ (aList['ThreatID'] == val) & (aList['Category'] == 'Denial Of Service'), 'DestinationType']
        
        if (valD.size >= 1):
            aList.at[ j, 'Destination'] = valD.iloc[0]
            aList.at[ j, 'DestinationType'] = dType.iloc[0]

     if  (aRow['Category'] == 'Information Disclosure') & (aRow['IFlag'] > 1) & (aRow['Description'].endswith("authorization settings.") == True) & (aRow['Source'] == 'Null') & (aRow['Destination'] == 'Null') :
        val = aRow['ThreatID'] - 1;
        
        valS = aList.loc[ (aList['ThreatID'] == val) & (aList['Category'] == 'Spoofing'), 'Source']
        sType = aList.loc[ (aList['ThreatID'] == val) & (aList['Category'] == 'Spoofing'), 'SourceType']

        if (valS.size >= 1):
            aList.at[ j, 'Source'] = valS.iloc[0]
            aList.at[ j, 'SourceType'] = sType.iloc[0]
        
        valD = aList.loc[ (aList['ThreatID'] == val) & (aList['Category'] == 'Spoofing'), 'Destination']
        dType = aList.loc[ (aList['ThreatID'] == val) & (aList['Category'] == 'Spoofing'), 'DestinationType']
        
        if (valD.size >= 1):
            aList.at[ j, 'Destination'] = valD.iloc[0]
            aList.at[ j, 'DestinationType'] = dType.iloc[0]



count = 0;
tp = pd.DataFrame()

for j, aRow in aList.iterrows():

    if  ((aRow['RepeatedElseWhere'] == True) & (aRow['RepeatedInCategory'] == 'Information Disclosure')):

        for l in range(1,3):
            # Keep these same
            tp.at[ (count+l), 'ThreatID'] = int(aRow['ThreatID']);
            tp.at[ (count+l), 'Interaction'] = aRow['Interaction'];
            tp.at[ (count+l), 'Category'] = aRow['Category'];
            tp.at[ (count+l), 'Description'] = aRow['Description'];
            tp.at[ (count+l), 'Title'] = aRow['Title'];
            tp.at[ (count+l), 'IFlag'] = int(aRow['IFlag']);
            tp.at[ (count+l), 'Source'] = aRow['Source'];
            tp.at[ (count+l), 'SourceType'] = aRow['SourceType'];
            tp.at[ (count+l), 'Destination'] = aRow['Destination'];
            tp.at[ (count+l), 'DestinationType'] = aRow['DestinationType'];

            # Update these
            tp.at[ (count+l), 'RepeatedElseWhere'] = False;
            tp.at[ (count+l), 'RepeatedInCategory'] = False;
            if ( l == 1 ):
                tp.at[ (count+l), 'Effect'] = 'Information not intended for disclosure';
            else:  
                tp.at[ (count+l), 'Effect'] = 'Data Flow Sniffing';
                
        count = count + 2;

for j, aRow in aList.iterrows():

    if  ((aRow['RepeatedElseWhere'] == True) & (aRow['RepeatedInCategory'] == 'Denial Of Service')):

        for l in range(1,5):
            # Keep these same
            tp.at[ (count+l), 'ThreatID'] = int(aRow['ThreatID']);
            tp.at[ (count+l), 'Interaction'] = aRow['Interaction'];
            tp.at[ (count+l), 'Category'] = aRow['Category'];
            tp.at[ (count+l), 'Description'] = aRow['Description'];
            tp.at[ (count+l), 'Title'] = aRow['Title'];
            tp.at[ (count+l), 'IFlag'] = int(aRow['IFlag']);
            tp.at[ (count+l), 'Source'] = aRow['Source'];
            tp.at[ (count+l), 'SourceType'] = aRow['SourceType'];
            tp.at[ (count+l), 'Destination'] = aRow['Destination'];
            tp.at[ (count+l), 'DestinationType'] = aRow['DestinationType'];

            # Update these
            tp.at[ (count+l), 'RepeatedElseWhere'] = False;
            tp.at[ (count+l), 'RepeatedInCategory'] = False;
            if ( l == 1 ):
                tp.at[ (count+l), 'Effect'] = 'Resource consumption';
            elif ( l == 2 ):
                tp.at[ (count+l), 'Effect'] = 'Crashes';
            elif ( l == 3 ): 
                tp.at[ (count+l), 'Effect'] = 'Prevent access to data store';
            else:  
                tp.at[ (count+l), 'Effect'] = 'Interrupt data flowing';
                
        count = count + 4;

for j, aRow in aList.iterrows():

    if  ((aRow['RepeatedElseWhere'] == True) & (aRow['RepeatedInCategory'] == 'Elevation Of Privilege')):

        for l in range(1,5):
            # Keep these same
            tp.at[ (count+l), 'ThreatID'] = int(aRow['ThreatID']);
            tp.at[ (count+l), 'Interaction'] = aRow['Interaction'];
            tp.at[ (count+l), 'Category'] = aRow['Category'];
            tp.at[ (count+l), 'Description'] = aRow['Description'];
            tp.at[ (count+l), 'Title'] = aRow['Title'];
            tp.at[ (count+l), 'IFlag'] = int(aRow['IFlag']);
            tp.at[ (count+l), 'Source'] = aRow['Source'];
            tp.at[ (count+l), 'SourceType'] = aRow['SourceType'];
            tp.at[ (count+l), 'Destination'] = aRow['Destination'];
            tp.at[ (count+l), 'DestinationType'] = aRow['DestinationType'];

            # Update these
            tp.at[ (count+l), 'RepeatedElseWhere'] = False;
            tp.at[ (count+l), 'RepeatedInCategory'] = False;
            if ( l == 1 ):
                tp.at[ (count+l), 'Effect'] = 'impersonate';
            elif ( l == 2 ):
                tp.at[ (count+l), 'Effect'] = 'change the flow of program execution';
            elif ( l == 3 ): 
                tp.at[ (count+l), 'Effect'] = 'remotely execute code';
            else:  
                tp.at[ (count+l), 'Effect'] = 'Cross-site request forgery';
                
        count = count + 4;



aList = aList.append(tp, sort = False)


# Final Attack List Compilation

# Create Attack List
aList.insert(0, "AttackID", pd.Series(np.arange(1,len(aList)+1,1)) , True) 

# Export AttackList to csv
aList.to_csv(attackFile + '.csv')

# Export AttackList to Excel
aList.to_excel(attackFile + '.xlsx', index = False)

print('\nSuccess!\n')

