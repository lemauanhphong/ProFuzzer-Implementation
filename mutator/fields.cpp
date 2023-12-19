#include "fields.h"

Field::Field(int l, int r, int type)
{
    this->l = l;
    this->r = r;
    this->type = type;
};

int Field::getL() { return l; }
int Field::getR() { return r; }
int Field::getType() { return type; }

Assertion::Assertion(int l, int r, map<int, vector<string>> *constant) : Field(l, r, 0)
{
    constant = constant;
}

Rawdata::Rawdata(int l, int r) : Field(l, r, 1) {}

Enumeration::Enumeration(int l, int r, map<int, vector<string>> *constant) : Field(l, r, 2)
{
    constant = constant;
}

Loopcount::Loopcount(int l, int r, int le, int ri) : Field(l, r, 3)
{
    this->r = {le, ri};
}

Offset::Offset(int l, int r, int v) : Field(l, r, 4)
{
    this->v = v;
}

Size::Size(int l, int r, int v) : Field(l, r, 5)
{
    this->v = v;
}