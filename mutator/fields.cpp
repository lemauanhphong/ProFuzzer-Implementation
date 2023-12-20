#include "fields.h"

vector<string> Field::SizeField = {"ma", "mi"};
vector<string> Field::OffsetField = {"ma", "mi"};
vector<string> Field::RawDataField = {"\xff\xff", "\x00\x00"};
vector<string> Field::BoundaryValue = {"\x01", "\x2d", "\x7b", "\x02"};

Field::Field(int l, int r, int type)
{
    this->l = l;
    this->r = r;
    this->type = type;
};

Field::~Field() {}

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

Offset::Offset(int l, int r, size_t v) : Field(l, r, 4)
{
    this->v = v;
}

void Offset::setV(size_t v)
{
    this->v = v;
}

Size::Size(int l, int r, size_t v) : Field(l, r, 5)
{
    this->v = v;
}

void Size::setV(size_t v)
{
    this->v = v;
}
