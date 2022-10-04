# %load malware_test.py
"""
this file extracts the required information of a given file using the library PE

"""

import pefile
import os
import array
import math
import pickle
import joblib
import pefile
import pandas
import csv
import os, sys
import json
import sys
import argparse


def get_entropy(data):
    if len(data) == 0:
        return 0.0
    occurences = array.array('L', [0] * 256)
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)

    return entropy


def get_resources(pe):
    """Extract resources :
    [entropy, size]"""
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData,
                                                   resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)

                                resources.append([entropy, size])
        except Exception as e:
            return resources
    return resources


def get_version_info(pe):
    """Return version infos"""
    res = {}
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    res[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                res[var.entry.items()[0][0]] = var.entry.items()[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
        res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
        res['os'] = pe.VS_FIXEDFILEINFO.FileOS
        res['type'] = pe.VS_FIXEDFILEINFO.FileType
        res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
        res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
        res['signature'] = pe.VS_FIXEDFILEINFO.Signature
        res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return res




# extract the info for a given file
def extract_info(fpath):
    count_suspicious_functions = 0
    number_packers = 0
    name_packers = []
    with open('name_packers.txt') as f:
        name_packers = f.readlines()
    name_packers = [x.strip() for x in name_packers]

    res = {}
    pe = pefile.PE(fpath)
    res['Machine'] = pe.FILE_HEADER.Machine
    res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
    res['Characteristics'] = pe.FILE_HEADER.Characteristics
    res['NumberOfSymbols'] = pe.FILE_HEADER.NumberOfSymbols
    res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
    res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
    res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
    res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
    res['Magic'] = pe.OPTIONAL_HEADER.Magic
    res['e_ss'] = pe.DOS_HEADER.e_ss
    res['e_magic'] = pe.DOS_HEADER.e_magic
    res['e_cblp'] = pe.DOS_HEADER.e_cblp
    res['e_cp'] = pe.DOS_HEADER.e_cp
    res['e_crlc'] = pe.DOS_HEADER.e_crlc
    res['e_cparhdr'] = pe.DOS_HEADER.e_cparhdr
    res['e_minalloc'] = pe.DOS_HEADER.e_minalloc
    res['e_maxalloc'] = pe.DOS_HEADER.e_maxalloc
    res['e_ss'] = pe.DOS_HEADER.e_ss
    res['e_sp']= pe.DOS_HEADER.e_sp
    res['e_csum']= pe.DOS_HEADER.e_csum
    res['e_ip']= pe.DOS_HEADER.e_ip
    res['e_cs']= pe.DOS_HEADER.e_cs
    res['e_lfarlc']= pe.DOS_HEADER.e_lfarlc
    res['e_ovno']= pe.DOS_HEADER.e_ovno
    res['e_oemid']= pe.DOS_HEADER.e_oemid
    res['e_oeminfo']= pe.DOS_HEADER.e_oeminfo
    res['e_lfanew']= pe.DOS_HEADER.e_lfanew
    try:
        res['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
    except AttributeError:
        res['BaseOfData'] = 0
    res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
    res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
    res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
    res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
    res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
    res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
    res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
    res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
    res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
    res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
    res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    res['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
    res['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
    res['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
    res['PointerToSymbolTable'] = pe.FILE_HEADER.PointerToSymbolTable


    # Sections
    res['SectionsNb'] = len(pe.sections)
    list_entropy = []
    for x in pe.sections:
        list_entropy.append(x.get_entropy())
    #entropy = map(lambda x: x.get_entropy(), pe.sections)
    entropy = map(lambda x: x.get_entropy(), pe.sections)
    res['SectionsMeanEntropy'] = sum(list_entropy) / float(len(list_entropy))
    res['SectionsMinEntropy'] = min(list_entropy)
    res['SectionsMaxEntropy'] = max(list_entropy)

    try:
        res['SectionMinEntropy'] = min(entropy)
    except (ValueError, TypeError):
        res['SectionMinEntropy'] = 0
    try:
        res['SectionMaxEntropy'] = max(entropy)
    except (ValueError, TypeError):
        res['SectionMaxEntropy'] = 0

    raw_sizes = list(map(lambda x: x.SizeOfRawData, pe.sections))

    for x in pe.sections:
        list_entropy.append(x.SizeOfRawData)
    res['SectionsMeanRawsize'] = sum(raw_sizes) / float(len(raw_sizes))
    res['SectionsMinRawsize'] = min(raw_sizes)
    res['SectionsMaxRawsize'] = max(raw_sizes)
    try:
        res['SectionMaxRawsize'] = max(raw_sizes)
    except (ValueError, TypeError):
        res['SectionMaxRawsize'] = 0


    try:
        res['SectionMinRawsize'] = min(raw_sizes)
    except (ValueError, TypeError):
        res['SectionMinRawsize'] = 0


    virtual_sizes = list(map(lambda x: x.Misc_VirtualSize, pe.sections))

    res['SectionMeanVirtualsize'] = sum(virtual_sizes) / float(len(virtual_sizes))
    res['SectionMinVirtualsize'] = min(virtual_sizes)
    res['SectionMaxVirtualsize'] = max(virtual_sizes)

    pointer_raw_data = list(map(lambda x: x.PointerToRawData, pe.sections))
    try:
        res['SectionMaxPointerData'] = max(pointer_raw_data)
    except (ValueError, TypeError):
        res['SectionMaxPointerData'] = 0
    virtual_address = map(lambda x: x.VirtualAddress, pe.sections)

    try:
        res['SectionMaxVirtualsize'] = max(virtual_sizes)
    except (ValueError, TypeError):
        res['SectionMaxVirtualsize'] = 0
    try:
        res['SectionMaxVirtualsize'] = max(virtual_sizes)
    except (ValueError, TypeError):
        res['SectionMaxVirtualsize'] = 0

    try:
        res['SectionMaxVirtual'] = max(virtual_address)
    except (ValueError, TypeError):
        res['SectionMaxVirtual'] = 0

    try:
        res['SectionMinVirtual'] = min(virtual_address)
    except (ValueError, TypeError):
        res['SectionMinVirtual'] = 0

    try:
        res['SectionMinPointerData'] = min(pointer_raw_data)
    except (ValueError, TypeError):
        res['SectionMinPointerData'] = 0

    try:
        for entry in pe.sections:
            try:
                entry.Name.decode('utf-8')
            except Exception:
                number_packers += 1
            if entry.Name in name_packers:
                number_packers += 1

        res['SuspiciousNameSection'] = number_packers
    except AttributeError as e:
        res['SuspiciousNameSection'] = 0
    try:
        res['SectionsLength'] = len(pe.sections)
    except (ValueError, TypeError):
        res['SectionsLength'] = 0
    characteristics = map(lambda x:x.Characteristics, pe.sections)
    try:
        res['SectionMaxChar'] = max(characteristics)
    except (ValueError, TypeError):
        res['SectionMaxChar'] = 0

    try:
        res['SectionMinChar'] = min(characteristics)
    except (ValueError, TypeError):
        res['SectionMainChar'] = 0

    # Imports
    try:
        res['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
        imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        res['ImportsNb'] = len(imports)
        res['ImportsNbOrdinal'] = len(list(filter(lambda x: x.name is None, imports)))
    except AttributeError:
        res['ImportsNbDLL'] = 0
        res['ImportsNb'] = 0
        res['ImportsNbOrdinal'] = 0

    try:
        res['DirectoryEntryImport'] = (len(pe.DIRECTORY_ENTRY_IMPORT))
        imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        res['DirectoryEntryImportSize'] = (len(imports))
    except AttributeError:
        res['DirectoryEntryImport'] = 10
        res['DirectoryEntryImportSize'] = 0
        # Exports
    try:
        res['DirectoryEntryExport'] = (len(pe.DIRECTORY_ENTRY_EXPORT.symbols))
    except AttributeError:
        # No export
        res['DirectoryEntryExport'] = 0

    res['ImageDirectoryEntryExport'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].VirtualAddress
    res['ImageDirectoryEntryImport'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress
    res['ImageDirectoryEntryResource'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']].VirtualAddress
    res['ImageDirectoryEntryException'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']].VirtualAddress
    res['ImageDirectoryEntrySecurity'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress

    # Exports
    try:
        res['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        # No export
        res['ExportNb'] = 0
    # Resources
    resources = get_resources(pe)
    res['ResourcesNb'] = len(resources)
    if len(resources) > 0:
        entropy = list(map(lambda x: x[0], resources))
        res['ResourcesMeanEntropy'] = sum(entropy) / float(len(entropy))
        res['ResourcesMinEntropy'] = min(entropy)
        res['ResourcesMaxEntropy'] = max(entropy)

        sizes = list(map(lambda x: x[1], resources))
        res['ResourcesMeanSize'] = sum(sizes) / float(len(sizes))
        res['ResourcesMinSize'] = min(sizes)
        res['ResourcesMaxSize'] = max(sizes)
    else:
        res['ResourcesNb'] = 0
        res['ResourcesMeanEntropy'] = 0
        res['ResourcesMinEntropy'] = 0
        res['ResourcesMaxEntropy'] = 0
        res['ResourcesMeanSize'] = 0
        res['ResourcesMinSize'] = 0
        res['ResourcesMaxSize'] = 0

    physical_address = map(lambda x: x.Misc_PhysicalAddress, pe.sections)
    try:
        res['SectionMaxPhysical'] = max(physical_address)
    except (ValueError, TypeError):
        res['SectionMaxPhysical'] = 0
    try:
        res['SectionMinPhysical'] = min(physical_address)
    except (ValueError, TypeError):
        res['SectionMinPhysical'] = 0


    # Load configuration size
    try:
        res['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
    except AttributeError:
        res['LoadConfigurationSize'] = 0

    # Version configuration size
    try:
        version_infos = get_version_info(pe)
        res['VersionInformationSize'] = len(version_infos.keys())
    except AttributeError:
        res['VersionInformationSize'] = 0
    return res




def check_EXE_PE_Header(path):

    # Load classifier
    clf = joblib.load('classifier3.pkl')
    # load features
    features = pickle.loads(open(os.path.join('features.pkl'), 'rb').read())
    data = extract_info(path)
    pe_features = list(map(lambda x: data[x], features))

    result = clf.predict([pe_features])[0]

    return result

if __name__ == '__main__':

    test = "K:\\Downloads\\installer.exe"
    # Load classifier
    clf = joblib.load('classifier3.pkl')
    # load features
    features = pickle.loads(open(os.path.join('featureslist.pkl'),'rb').read())
    data = extract_info(test)
    pe_features = list(map(lambda x: data[x], features))

    res = clf.predict([pe_features])[0]

    print(res)


#todo make method with parameter and pass in path