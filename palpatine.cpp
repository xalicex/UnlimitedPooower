#include <windows.h>
#include <accctrl.h>
#include <aclapi.h>
#include <winnt.h>
#include <stdio.h>
#include <lmcons.h>


//slightly modified version of https://docs.microsoft.com/en-us/windows/win32/secauthz/modifying-the-acls-of-an-object-in-c--
DWORD AddAceToObjectsSecurityDescriptor (
    HANDLE pszObjName,          // name of object
    SE_OBJECT_TYPE ObjectType,  // type of object
    LPTSTR pszTrustee,          // trustee for new ACE
    TRUSTEE_FORM TrusteeForm,   // format of trustee structure
    DWORD dwAccessRights,       // access mask for new ACE
    ACCESS_MODE AccessMode,     // type of ACE
    DWORD dwInheritance         // inheritance flags for new ACE
) 
{
    DWORD dwRes = 0;
    PACL pOldDACL = NULL, pNewDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS ea;

    if (NULL == pszObjName) 
        return ERROR_INVALID_PARAMETER;

    // Get a pointer to the existing DACL.

    dwRes = GetSecurityInfo(pszObjName, ObjectType, 
          DACL_SECURITY_INFORMATION,
          NULL, NULL, &pOldDACL, NULL, &pSD);
    if (ERROR_SUCCESS != dwRes) {
        printf( "GetSecurityInfo Error %u\n", dwRes );
        goto Cleanup; 
    }  

    // Initialize an EXPLICIT_ACCESS structure for the new ACE. 

    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = dwAccessRights;
    ea.grfAccessMode = AccessMode;
    ea.grfInheritance= dwInheritance;
    ea.Trustee.TrusteeForm = TrusteeForm;
    ea.Trustee.ptstrName = pszTrustee;

    // Create a new ACL that merges the new ACE
    // into the existing DACL.

    dwRes = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
    if (ERROR_SUCCESS != dwRes)  {
        printf( "SetEntriesInAcl error : %u\n", dwRes );
        goto Cleanup; 
    }else{
	  printf("SetEntriesAcl SUCCESS !\n");
	}  

    // Attach the new ACL as the object's DACL.

    dwRes = SetSecurityInfo(pszObjName, ObjectType, 
          DACL_SECURITY_INFORMATION,
          NULL, NULL, pNewDACL, NULL);
    if (ERROR_SUCCESS != dwRes)  {
        printf( "SetSecurityInfo error : %u\n", dwRes );
        goto Cleanup; 
    }else{
	  printf("SetSecurityInfo SUCCESS \n");
    }  

    Cleanup:

        if(pSD != NULL) 
            LocalFree((HLOCAL) pSD); 
        if(pNewDACL != NULL) 
            LocalFree((HLOCAL) pNewDACL); 

        return dwRes;
}

int main(int argc, char *argv[])
{
  //get pid from cmd argument
  int pid = atoi(argv[1]);
  DWORD dwRes = 0;


  //retrieve user
  char username[UNLEN+1];
  DWORD username_len = UNLEN+1;
  GetUserName(username, &username_len);

  //open process with permission to READ and WRITE DACL
  //User running this binary should be owner of the target process or have READ_CONTROL (read permission) and WRITE_DAC (write permission)
  HANDLE self = OpenProcess(READ_CONTROL | WRITE_DAC, FALSE, (DWORD) pid);
  if(self != NULL){
	printf("process open with ability to read and modify DACL! \n");	
	
	//Set Full Control for the current user on the target process
	AddAceToObjectsSecurityDescriptor(self, SE_KERNEL_OBJECT, (LPSTR)username,TRUSTEE_IS_NAME, GENERIC_ALL , GRANT_ACCESS, 0);
  }
  else{
	  dwRes = GetLastError();
	  printf("error in opening of the process. Code %u \n", dwRes);
  }
}
