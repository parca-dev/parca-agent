%module arguments

%{
#include "arguments.h"
%}

%rename(_bool_operator) operator bool;
%rename("%(camelcase)s") "";  // Apply camelCase renaming to everything

%rename(newfile) file;

// Make sure we handle the memory mangement of the returned string correctly
%typemap(go, out="1") const char* %{
    $result = CString($1);
    delete[] $1;
%}

// Suppress memory leak warning
%warnfilter(451);

%include "arguments.h"
