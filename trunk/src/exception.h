/**
 * DNS Exception 
 *
 * Copyright (C) 2014 - Michal Nezerka <michal.nezerka@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * 
 */

#ifndef _DNS_EXCEPTION_H
#define	_DNS_EXCEPTION_H

#include <exception>
#include <string>

namespace dns {

/**
 *  Exception class extends standard exception funtionality and adds it the text
 *  message to inform about the reason of the exception thrown.
 */
class Exception : public std::exception {
public:
    // Constructor
    // @param text Information text to be filled with the reasons of the exception
    Exception(const std::string& text) : m_text(text) { }
    Exception(const char *text) : m_text(text) { }
    virtual ~Exception() throw() { }

    // Returns the information text string
    virtual const char* what() const throw()
    {
        return m_text.data();
    }

private:
    std::string m_text;
};
}
#endif	/* _DNS_EXCEPTION_H */

