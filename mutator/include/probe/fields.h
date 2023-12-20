#include <bits/stdc++.h>

using namespace std;

class Field
{
private:
    int l,
        r,
        type;

public:
    Field(int l, int r, int type);
    virtual ~Field();
    int getL();
    int getR();
    int getType();

    static vector<string> SizeField;
    static vector<string> RawDataField;
    static vector<string> OffsetField;
    static vector<string> BoundaryValue;
};

class Assertion : public Field
{
private:
    map<int, vector<string>> *constant;

public:
    Assertion(int l, int r, map<int, vector<string>> *constant);
};

class Rawdata : public Field
{
public:
    Rawdata(int l, int r);
};

class Enumeration : public Field
{
private:
    map<int, vector<string>> *constant;

public:
    Enumeration(int l, int r, map<int, vector<string>> *constant);
};

class Loopcount : public Field
{
private:
    pair<int, int> r;

public:
    Loopcount(int l, int r, int le, int ri);
};

class Offset : public Field
{
private:
    size_t v;

public:
    Offset(int l, int r, size_t v);
    void setV(size_t v);
};

class Size : public Field
{
private:
    size_t v;

public:
    Size(int l, int r, size_t v);
    void setV(size_t v);
};